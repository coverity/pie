String actual = new File(basedir, "output.policy").getText("UTF-8")
String expected = new File(basedir, "expectedOutput.policy").getText("UTF-8")

assert actual == expected
