Development components. Original vendor files are downloaded separately.
Build with Python, Zig 0.17.0-dev.2251+1175a3e99 and Inno Setup 6.7.3.
python build_installer.py /path/to/zig.exe /path/to/ISCC.exe /new/output/folder
The generated source embeds the included, source-provided trackpad helper.
Use build_trackpad.py with the same Zig compiler to rebuild that helper.
Compiler and setup packaging timestamps may affect byte reproducibility.
