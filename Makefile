# My makefile exploits features of GNU Make that other Makes
# do not have.  Because it is a common mistake for people to try to build
# stuff with a different Make, I have this makefile that does nothing
# but tell the user to use GNU Make.

# If the user were using GNU Make now, this file would not get used because
# GNU Make uses a makefile named "GNUmakefile" in preference to "Makefile"
# if it exists.  We have a "GNUmakefile".

all merge install clean dep:
	@echo "You must use GNU Make to build this stuff.  You are running "
	@echo "some other Make.  GNU Make may be installed on your system "
	@echo "with the name 'gmake'.  If not, see "
	@echo "http://www.gnu.org/software ."
	@echo
