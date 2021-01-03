/* serial2net SSH - ComTester
 *
 * The Software "ComTester" is a handling tool for the diploma project
 * "serial2net" of hf-ict and should provide the possibility to users
 * testing there serial-ethernet converter installations.
 *
 * Copyright (C) 2016 Michael Ramstein 	<m.mislin@serial2net.ch>
 * Copyright (C) 2016 Michael Mislin 	<m.ramstein@serial2net.ch>
 * Copyright (C) 2016 Pascal Probst 	<p.probst@serial2net.ch>
 *
 * The software includes the libssh2 library >https://www.libssh2.org>
 * libssh2 is open source licensed under the 3-clause BSD License.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, see <http://www.gnu.org/licenses/>.
 */

#include "widget.h"
#include "splashscreen.h"

#include <QApplication>
#include <QDesktopWidget>
#include <QDebug>
#include <qthread.h>

class I : public QThread
{
public:
    static void sleep(unsigned long secs) { QThread::sleep(secs); }
};
int main(int argc, char *argv[])
{
    QApplication a(argc, argv);

    QDesktopWidget wid;
    int screenWidth = wid.screen()->width();
    int screenHeight = wid.screen()->height();
    qDebug() << "Screen size width = " << screenWidth << "height = " << screenHeight;

    Widget libssh2;
    libssh2.hide();
    int widthWid = libssh2.width();
    int heighWid = libssh2.height();
    qDebug() << "Widget size x: " << widthWid << "y: " << heighWid;
    libssh2.move((screenWidth/2)-(widthWid/2), (screenHeight/2)-(heighWid/2));
    qDebug() << "Widget position x = " << (screenWidth/2)-(widthWid/2) << "y = " << (screenHeight/2)-(heighWid/2);

    SplashScreen *splash = new SplashScreen(&a);
    int widthSplash = splash -> width();
    int heightSplash = splash -> height();
    qDebug() << "Splash size x: " << widthSplash << "y: " << heightSplash;
    splash -> move((screenWidth/2)-(widthSplash/2), (screenHeight/2)-(heightSplash/2));
    qDebug() << "Splash position x = " << (screenWidth/2)-(widthSplash/2) << "y = " << (screenHeight/2)-(heightSplash/2);

    splash -> show();
    I::sleep(2);
    splash -> finish(&libssh2);
    libssh2.isVisible();

    libssh2.show();


    return a.exec();
}
