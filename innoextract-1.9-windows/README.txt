
=================================================================
 innoextract - A tool to unpack installers created by Inno Setup
=================================================================

Inno Setup (https://jrsoftware.org/isinfo.php) is a tool to create installers for Microsoft
Windows applications. innoextract allows to extract such installers under non-Windows systems
without running the actual installer using wine. innoextract currently supports installers
created by Inno Setup 1.2.10 to 6.0.5.

In addition to standard Inno Setup installers, innoextract also supports some modified Inno
Setup variants including Martijn Laan's My Inno Setup Extensions 3.0.6.1 as well as GOG.com's
Inno Setup-based game installers.

innoextract is available under the ZLIB license - see the LICENSE file.

See the website for Linux packages (https://constexpr.org/innoextract/#packages).


 Contact
=========

Website: https://constexpr.org/innoextract/

Author: Daniel Scharrer (https://constexpr.org/)


 Run
=====

To extract a setup file to the current directory run:

    innoextract <file>

A list of available options can be retrieved using

    innoextract --help

Documentation is also available as a man page:

    see doc/innoextract.txt


 Limitations
=============

 - There is no support for extracting individual components and limited support for filtering
   by name.

 - Included scripts and checks are not executed.

 - The mapping from Inno Setup variables like the application directory to subdirectories
   is hard-coded.

 - Names for data slice/disk files in multi-file installers must follow the standard naming scheme.

A perhaps more complete, but Windows-only, tool to extract Inno Setup files is innounp
(http://innounp.sourceforge.net/).

Extracting Windows installer executables created by programs other than Inno Setup is out of
the scope of this project. Some of these can be unpacked by the following programs:

 - cabextract: https://cabextract.org.uk/

 - unshield: https://github.com/twogood/unshield


 Disclaimer
============

This project is in no way associated with Inno Setup or https://jrsoftware.org/.
