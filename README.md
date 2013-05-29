IdaMassRename (Beta)
====================

This is an IDA Pro plugin to facilitate mass renaming of symbols. 
Default hotkey: Ctrl-r

Motivation
==========

There have been multiple times where I wanted to rename multiple symbols
(function or global names) in IDA, but found that there was no easy way of
doing so. I found it annoying to have to stop work to hack up some script to
rename these symbols each time and most of the time I would end up rename these
symbols manually. 

I always thought that such a simple thing could be done in seconds in a
powerful text editor like Vim or Sublime. This plugin allows just such a thing.
The original text is copied into the first window. This text can then be
modified in an external editor and pasted into the second window. A simple diff
is done between the two windows to find out which symbols have changed. The
modified symbols are then renamed after confirmation with the user.

More documentation to come shortly.

