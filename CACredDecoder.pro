TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += src/main.cpp
HEADERS +=

DISTFILES += \
    README.md


QMAKE_INCDIR += src
INCLUDEPATH += src
