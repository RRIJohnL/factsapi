dir /s /B *.java > sources.txt

set classpath=.
set classpath=%classpath%;./java-json.jar

set class=rriapi/*.class

"c:\Program Files\java\jdk-20\bin\javac" -cp %classpath% @sources.txt

"c:\Program Files\java\jdk-20\bin\jar" -cvfm rriapi.jar manifest.txt %class%

"c:\Program Files\java\jdk-20\bin\javac" -version

pause