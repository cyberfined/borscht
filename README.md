# borscht
Simple FTP server written in go.

# Usage
```bash
./borscht [FILE]...
```

Default port is 5000. All files and directories will be placed in root of FTP server.

# Implemented commands

* USER.
* PASS.
* SYST.
* TYPE.
* FEAT.
* PWD.
* CWD.
* PASV.
* SIZE.
* LIST.
* RETR.
* QUIT.

# TODO

* Implement active mode aka PORT command.
* Implement STOR command.
