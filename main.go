package main

import (
    "net"
    "os"
    "io"
    "io/ioutil"
    "path"
    "strings"
    "bytes"
    "sync/atomic"
    "fmt"
)

const (
    ListenPort = 5000
    MinPort    = 1234
    NumPorts   = 65536-1234-1
)

type PortState struct {
    Ports    [2048]uint32
    LastPort uint16
    Lock     atomic.Value
}

type State struct {
    Files    map[string][]File
    CurDir   string
    CmdConn  net.Conn
    FileConn net.Conn
    IsUser   bool
    IsPass   bool
    IsPasv   bool
    IsTrans  bool
    Pstate   *PortState
    Run      bool
    IPAddr   net.IP
}

type File struct {
    Name  string
    Path  string
    IsDir bool
    Size  int64
}

func getPort(pstate *PortState) (uint16, bool) {
    for {
        lock := pstate.Lock.Load().(bool)
        if lock {
            continue
        }
        pstate.Lock.Store(true)

        res := pstate.LastPort
        isFound := false
        for numStates := 0; numStates < NumPorts; numStates++ {
            if pstate.Ports[res >> 5] & uint32(1 << (res & 31)) == 0 {
                isFound = true
                break
            }

            if res == 65535 {
                res = MinPort
            } else {
                res++
            }
        }

        if isFound {
            pstate.Ports[res >> 5] |= uint32(1 << (res & 31))
            pstate.LastPort = res
        }
        pstate.Lock.Store(false)
        return res, isFound
    }
    panic("Never executed")
}

func getFile(body []byte, st *State, isDir, isSet bool) *File {
    var curDir string
    var isChanged bool
    var paths []string
    var res *File
    var dummy File

    if len(body) < 1 {
        return nil
    }

    if body[0] == '/' {
        curDir = "./"
        body = body[1:]
    } else {
        curDir = st.CurDir
    }

    if len(body) == 0 && isDir {
        res = &dummy
        if isSet {
            st.CurDir = "./"
        }
    } else if len(body) > 0 {
        paths = strings.Split(string(body), "/")
    }

    for i, p := range paths {
        files := st.Files[curDir]
        

        if p == ".." {
            curDir = path.Dir(curDir)
            if isDir {
                if i == len(paths)-1 {
                    if isSet {
                        if len(curDir) == 1 {
                            st.CurDir = "./"
                        } else {
                            st.CurDir = curDir
                        }
                    }
                    res = &dummy
                }
            }
            continue
        } else if len(p) == 0 && i == len(paths)-1 && isDir {
            st.CurDir = curDir 
            res = &dummy
            break
        }

        isChanged = false
        for j, f := range files {
            if p == f.Name {
                if i == len(paths) - 1 && isDir == f.IsDir {
                    if isDir && isSet {
                        st.CurDir = path.Join(curDir, f.Name)
                    }
                    res = &files[j]
                } else if f.IsDir {
                    curDir = path.Join(curDir, f.Name)
                    isChanged = true
                    break
                } else {
                    break
                }
            }
        }

        if !isChanged {
            break
        }
    }

    return res
}

type CmdFn func(body []byte, st *State) error

func PrintCmd(msg []byte) CmdFn {
    return func(body []byte, st *State) error {
        var err error
        if !st.IsUser || !st.IsPass {
            _, err = st.CmdConn.Write([]byte("530 Please login with USER and PASS\n"))
            if err != nil {
                return err
            }
        }

        _, err = st.CmdConn.Write(msg)
        return err
    }
}

func AuthCmd(cmd CmdFn) CmdFn {
    return func(body []byte, st *State) error {
        var err error
        if !st.IsUser || !st.IsPass {
            _, err = st.CmdConn.Write([]byte("530 Please login with USER and PASS\n"))
            return err
        }
        return cmd(body, st)
    }
}

func PasvCmd(cmd CmdFn) CmdFn {
    return func(body []byte, st *State) error {
        var err error
        if !st.IsUser || !st.IsPass {
            _, err = st.CmdConn.Write([]byte("530 Please login with USER and PASS\n"))
            return err
        }

        if !st.IsPasv {
            _, err = st.CmdConn.Write([]byte("425 Use PORT or PASV first.\n"))
            return err
        }
        st.IsPasv = false
        err = cmd(body, st)
        st.FileConn.Close()
        return err
    }
}

func userHandler(body []byte, st *State) error {
    st.IsUser = true
    _, err := st.CmdConn.Write([]byte("331 Please specify the password.\n"))
    return err
}

func passHandler(body []byte, st *State) error {
    var err error
    if !st.IsUser {
        _, err = st.CmdConn.Write([]byte("503 Login with USER first.\n"))
        return err
    }

    st.IsPass = true
    _, err = st.CmdConn.Write([]byte("230 Login successful.\n"))
    return err
}

func pwdHandler(body []byte, st *State) error {
    dir := st.CurDir
    if len(dir) > 1 && dir[0] == '.' {
        dir = dir[2:]
    }
    _, err := st.CmdConn.Write([]byte(fmt.Sprintf("257 \"/%s\" is the current directory\n", dir)))
    return err
}

func cwdHandler(body []byte, st *State) error {
    var err error
    if getFile(body, st, true, true) != nil {
        _, err = st.CmdConn.Write([]byte("250 Directory successfully changed.\n"))
    } else {
        _, err = st.CmdConn.Write([]byte("550 Failed to change directory.\n"))
    }
    return err
}

func portHandler(body []byte, st *State) error {
    return nil
}

func pasvHandler(body []byte, st *State) error {
    var err error

    if st.IsPasv {
        st.FileConn.Close()
    }

    port, isFound := getPort(st.Pstate)
    if !isFound {
        _, err = st.CmdConn.Write([]byte("425 All ports are used.\n"))
        return err
    }

    _, err = st.CmdConn.Write([]byte(fmt.Sprintf("227 Entering Passive Mode (%d,%d,%d,%d,%d,%d).\n",
                              st.IPAddr[12], st.IPAddr[13], st.IPAddr[14], st.IPAddr[15], (port & 0xff00) >> 8, port & 0xff)))
    if err != nil {
        return err
    }

    st.IsPasv = true
    ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: st.IPAddr, Port: int(port)})
    if err != nil {
        return err
    }
    st.FileConn, err = ln.Accept()
    return err
}

func sizeHandler(body []byte, st *State) error {
    var err error
    file := getFile(body, st, false, false)
    if file != nil {
        _, err = st.CmdConn.Write([]byte(fmt.Sprintf("213 %d\n", file.Size)))
    } else {
        _, err = st.CmdConn.Write([]byte("550 Could not get file size.\n"))
    }
    return err
}

func listHandler(body []byte, st *State) error {
    var err error
    var file *File
    dummy := File {
        Path: st.CurDir,
    }

    if len(body) != 0 && body[0] != '-' {
        file = getFile(body, st, true, false)
    } else {
        file = &dummy
    }
    if file != nil {
        files := st.Files[file.Path]

        var line []byte
        for _, f := range files {
            if !f.IsDir {
                line = []byte(fmt.Sprintf("-rw------- 1 1002 1002 %d Jul 29 2018 %s\n", f.Size, f.Name))
            } else {
                line = []byte(fmt.Sprintf("drwx------ 3 1002 1002 %d Jul 29 2018 %s\n", f.Size, f.Name))
            }

            _, err = st.FileConn.Write(line)
            if err != nil {
                return err
            }
        }
    }

    _, err = st.CmdConn.Write([]byte("150 Here comes the directory listing.\n226 Directory send OK.\n"))
    return err
}

func retrHandler(body []byte, st *State) error {
    var err error
    var buf []byte
    var fd *os.File
    var n int

    file := getFile(body, st, false, false)
    if file == nil {
        goto err
    }

    buf = make([]byte, 4096)
    fd, err = os.Open(file.Path)
    if err != nil {
        goto err
    }

    _, err = st.CmdConn.Write([]byte(fmt.Sprintf("150 Opening BINARY mode data connection for %s (%d bytes).\n", file.Name, file.Size)))
    if err != nil {
        goto err
    }

    for {
        n, err = fd.Read(buf)
        if err != nil {
            if err == io.EOF {
                break
            }
            goto err
        }
        _, err = st.FileConn.Write(buf[:n])
        if err != nil {
            goto err
        }
    }

    _, err = st.CmdConn.Write([]byte("226 Transfer complete.\n"))
    return err
err:
    _, err = st.CmdConn.Write([]byte("550 Failed to open file.\n"))
    return err
}

func quitHandler(body []byte, st *State) error {
    st.Run = false
    _, err := st.CmdConn.Write([]byte("221 Goodbye.\n"))
    return err
}

var cmds = map[string]CmdFn {
    "USER": userHandler,
    "PASS": passHandler,
    "SYST": PrintCmd([]byte("215 UNIX TYPE: L8\n")),
    "TYPE": PrintCmd([]byte("200 Type set to I\n")),
    "FEAT": PrintCmd([]byte("211-Features:\n SIZE\n UTF8\n211 End\n")),
    "PWD":  AuthCmd(pwdHandler),
    "CWD":  AuthCmd(cwdHandler),
    "PORT": AuthCmd(portHandler),
    "PASV": AuthCmd(pasvHandler),
    "SIZE": AuthCmd(sizeHandler),
    "LIST": PasvCmd(listHandler),
    "RETR": PasvCmd(retrHandler),
    "QUIT": quitHandler,
}

func handleConn(files map[string][]File, pstate *PortState, conn net.Conn) {
    st := &State {
        Files:   files,
        CurDir:  "./",
        CmdConn: conn,
        IsUser:  false,
        IsPass:  false,
        IsPasv:  false,
        IsTrans: false,
        Pstate:  pstate,
        Run:     true,
        IPAddr:  net.ParseIP(strings.Split(conn.LocalAddr().String(), ":")[0]),
    }
    buf := make([]byte, 512)

    defer conn.Close()
    defer func() {
        if st.IsPasv {
            st.FileConn.Close()
        }
    }()

    _, err := conn.Write([]byte("220 Welcome to server\n"))
    if err != nil {
        fmt.Fprintln(os.Stderr, err)
        return
    }

    for st.Run {
        n, err := conn.Read(buf)
        if err != nil {
            fmt.Fprintln(os.Stderr, err)
            break
        }

        fmt.Printf("%s", buf[:n])

        toks := bytes.Split(buf[:n], []byte(" "))
        isImpl := false
        cmd := CmdFn(nil)
        arg := []byte(nil)
        if len(toks) > 0 {
            if bytes.HasSuffix(toks[0], []byte("\r\n")) {
                toks[0] = toks[0][:len(toks[0])-2]
            } else if len(toks) > 1 && bytes.HasSuffix(toks[len(toks)-1], []byte("\r\n")) {
                arg = toks[len(toks)-1]
                arg = arg[:len(arg)-2]
            }

            cmd, isImpl = cmds[string(toks[0])]
        }

        if len(toks) < 1 || !isImpl {
            _, err = conn.Write([]byte("500 Unknown command.\n"))
        } else {
            err = cmd(arg, st)
        }

        if err != nil {
            fmt.Fprintln(os.Stderr, err)
            break
        }
    }
}

func readPath(files map[string][]File, cur, filepath string) error {
    inf, err := os.Stat(filepath)
    if err != nil {
        return err
    }

    fname := strings.ReplaceAll(inf.Name(), " ", "_")
    if inf.IsDir() {
        files[cur] = append(files[cur], File {fname, filepath, true, inf.Size()})
        fs, err := ioutil.ReadDir(filepath)
        if err != nil {
            return err
        }
        nextDir := path.Join(cur, fname)
        for _, f := range fs {
            err = readPath(files, nextDir, path.Join(filepath, f.Name()))
            if err != nil {
                return err
            }
        }
    } else {
        files[cur] = append(files[cur], File {fname, filepath, false, inf.Size()})
    }

    return nil
}

func main() {
    if len(os.Args) == 1 {
        fmt.Fprintf(os.Stderr, "Usage: %s [FILE]...\n", os.Args[0])
        return
    }

    files := make(map[string][]File)
    for i := 1; i < len(os.Args); i++ {
        err := readPath(files, "./", os.Args[i])
        if err != nil {
            fmt.Fprintln(os.Stderr, err)
            return
        }
    }

    pstate := &PortState {
        LastPort: 1234,
    }
    pstate.Ports[ListenPort >> 5] |= (1 << (ListenPort & 31))
    pstate.Lock.Store(false)

    ln, err := net.ListenTCP("tcp", &net.TCPAddr {IP: net.IPv4(0,0,0,0), Port: ListenPort})
    if err != nil {
        fmt.Println(err)
        return
    }

    for {
        conn, err := ln.Accept()
        if err != nil {
            fmt.Println(err)
            continue
        }
        go handleConn(files, pstate, conn)
    }
}
