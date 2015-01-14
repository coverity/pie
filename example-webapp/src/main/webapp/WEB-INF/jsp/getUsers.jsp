<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN"
   "http://www.w3.org/TR/html4/loose.dtd">
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<html>
  <body>
    <b>Users:</b><br/>
    <c:forEach var="user" items="${users}">
      ${user.username}<br/>
    </c:forEach>
  </body>
</html>