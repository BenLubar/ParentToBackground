ParentToBackground
==================

My development machine, my hobby project build server, and my gaming PC are the same computer. This poses a problem when my build server wants to start compiling a huge project while I'm playing a multiplayer game.

This little program solves the problem. Just have the build process (or some automated setup script that runs every so often) run `ParentToBackground.exe BuildServerExecutableName.exe` and the builds will be slightly slower but you'll be able to play video games or use Visual Studio uninterrupted.

**Disclaimer:** This program does use an undocumented Windows NT function and some undocumented enumeration values, so it's very likely to break after a Windows update. However, the function calls used in this program worked on Windows Vista and they still work on Windows 10 Creator's Update.
