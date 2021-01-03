#/* serial2net SSH - ComTester
# *
# * The Software "ComTester" is a handling tool for the diploma project
# * "serial2net" of hf-ict and should provide the possibility to users
# * testing there serial-ethernet converter installations.
# *
# * Copyright (C) 2016 Michael Mislin 	<aufdiewelle@hotmail.com>
# *
# * The software includes the libssh2 library >https://www.libssh2.org>
# * libssh2 is open source licensed under the 3-clause BSD License.
# *
# * This program is free software; you can redistribute it and/or modify
# * it under the terms of the GNU General Public License as published by
# * the Free Software Foundation; either version 3 of the License, or
# * (at your option) any later version.
# *
# * This program is distributed in the hope that it will be useful, but
# * WITHOUT ANY WARRANTY; without even the implied warranty of
# * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# * General Public License for more details.
# *
# * You should have received a copy of the GNU General Public License
# * along with this program; if not, see <http://www.gnu.org/licenses/>.
# */

#execute "conanfile.txt" at CLI with conan for build libs according OS
#command is depending on OS AND is just executed if project is not build
win32: system($$cmd.exe conan install . --profile msvc2019x86_64)
unix:  system($$xterm conan install --build libssh2)

#include librarys with conan
#CONFIG += conan_basic_setup
#include(conanbuildinfo.pri)

QT += core
QT += gui
QT += network
QT += widgets

greaterThan(QT_MAJOR_VERSION, 4): QT += widgets

CONFIG  += c++11

TARGET = ComTester
TEMPLATE = app

INCLUDEPATH += $$PWD/
DEPENDPATH += $$PWD/

#include dyanamic links according OS
win32: LIBS += -L$$PWD"\bin" -llibssh2
win32: LIBS += -L$$PWD"\bin" -lws2_32
unix: LIBS += -L$$PWD/lib/ -lssh2

RESOURCES += resource.qrc

SOURCES += main.cpp\
        widget.cpp \
    sshtunnel.cpp \
    tcpsocket.cpp \
    textinterface.cpp \
    aboutdialog.cpp \
    aboutwidget.cpp \
    splashscreen.cpp \
    version.cpp

HEADERS  += widget.h \
    sshtunnel.h \
    tcpsocket.h \
    textinterface.h \
    aboutdialog.h \
    aboutwidget.h \
    splashscreen.h \
    version.h

FORMS +=

#set properties of deployed execute file
QMAKE_TARGET_DESCRIPTION = Communication test serial2net
VERSION = 1.0.5.0
QMAKE_TARGET_PRODUCT = ComTester
QMAKE_TARGET_COMPANY = www.serial2net.ch
QMAKE_TARGET_COPYRIGHT = serial2net(C)
RC_ICONS = resource/serial2netIco.ico

