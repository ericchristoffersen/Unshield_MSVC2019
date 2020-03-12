This is a quick port of the unshield github project so it can build
in msvc 2019 and run as a native windows command line app. I only
build for x64 but debug and release both work fine.

To build for windows:

1) Download msvc 2019 express edition (the free one) and install the c++ component.
2) Enlist in this project.
3) Download zlib sources and build them. I put the headers and my
   build libs at:
     d:\zlib-1.2.11
4) Open the vcproj file in msvc2019.
5) Go to project properties and edit vc++ directories:
   Add zlib header dir to headers.
   Add zlib lib dir to libs.
6) Go to project properties and edit linker/input:
   Add zlib.lib in the Additional Dependencies field.
7) To run in debugger, add a reasonable debugger command line.
   Edit properties/debugging/command arguments to something like:
     -d "d:\unpacktest\outputdir" x "d:\unpacktest\data1.cab"
