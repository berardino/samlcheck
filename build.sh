#/bin/bash
mvn clean compile assembly:single

mkdir -p bin

mv target/samlcheck-*-jar-with-dependencies.jar bin/samlcheck.jar
