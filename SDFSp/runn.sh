#!/bin/sh
cd src
javac -cp ../lib/bcprov-ext-jdk15on-148.jar *.java
java -cp .:../lib/bcprov-ext-jdk15on-148.jar SDFS

