# KISA GuidLine Bug Pattern
1. SQL 삽입
  - FindBugs
    - [CUSTOM_INJECTION](https://find-sec-bugs.github.io/bugs.htm#CUSTOM_INJECTION)
    - [SQL_INJECTION]()
    - [SQL_INJECTION_TURBINE]()
    - [SQL_INJECTION_HIBERNATE]()
    - [SQL_INJECTION_JDO]()
    - [SQL_INJECTION_JPA]()
    - [SQL_INJECTION_SPRING_JDBC]()
    - [SQL_INJECTION_JDBC]()
    - [SCALA_SQL_INJECTION_SLICK]()
    - [SCALA_SQL_INJECTION_ANORM]()
    - [SQL_INJECTION_ANDROID]()
    - [AWS_QUERY_INJECTION]()
    - [SQL: Nonconstant string passed to execute or addBatch method on an SQL statement]()
    - [SQL: A prepared statement is generated from a nonconstant String]()
  - LAPSE+
    - [SQL Injection]()
  - SonarQube
    - [SQL binding mechanisms should be used]()
2. 경로조작 및 자원삽입
  - FindBugs
    - [PATH_TRAVERSAL_IN]()
    - [PATH_TRAVERSAL_OUT]()
    - [SCALA_PATH_TRAVERSAL_IN]()
    - [STRUTS_FILE_DISCLOSURE]()
    - [SPRING_FILE_DISCLOSURE]()
    - [REQUESTDISPATCHER_FILE_DISCLOSURE]()
    - [EXTERNAL_CONFIG_CONTROL]()
    - [BEAN_PROPERTY_INJECTION]()
    - [PT: Absolute path traversal in servlet]()
    - [PT: Relative path traversal in servlet]()
  - LAPSE+
    - [Path Traversal]()
  - SonarQube
    - [Dependencies should not have "system" scope]()
3. 크로스사이트 스크립트
  - FindBugs
    - [XSS_REQUEST_WRAPPER]()
    - [JSP_JSTL_OUT]()
    - [XSS_JSP_PRINT]()
    - [XSS_SERVLET]()
    - [ANDROID_GEOLOCATION]()
    - [ANDROID_WEB_VIEW_JAVASCRIPT]()
    - [ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE]()
    - [HTTPONLY_COOKIE]()
    - [SCALA_XSS_TWIRL]()
    - [SCALA_XSS_MVC_API]()
    - [XSS: JSP reflected cross site scripting vulnerability]()
    - [XSS: Servlet reflected cross site scripting vulnerability in error page]()
    - [XSS: Servlet reflected cross site scripting vulnerability]()
  - LAPSE+
    - [Cross-Site-Scripting(XSS)]()
4. 운영체제 명령어 삽입
  - FindBugs
    - [COMMAND_INJECTION]()
    - [SCALA_COMMAND_INJECTION]()
  - LAPSE+
    - [Command Injection]()
  - SonarQube
    - [Values passed to OS commands should be sanitized]()
5. 위험한 형식 파일 업로드
  - FindBugs
    - [WEAK_FILENAMEUTILS]()
    - [FILE_UPLOAD_FILENAME]()
6. 신뢰되지 않는 URL 주소로 자동접속 연결
  - FindBugs
    - [UNVALIDATED_REDIRECT]()
    - [PLAY_UNVALIDATED_REDIRECT]()
    - [SPRING_UNVALIDATED_REDIRECT]()
  - LAPSE+
    - [URL Tampering]()
7. XQuery 삽입
  - FindBugs
    - [XMLStreamReader]()
    - [XXE_SAXPARSER]()
    - [XXE_XMLREADER]()
    - [XXE_DOCUMENT]()
    - [XXE_DTD_TRANSFORM_FACTORY]()
    - [XXE_XSLT_TRANSFORM_FACTORY]()
    - [XML_DECODER]()
    - [JSP_XSLT]()
    - [MALICIOUS_XSLT]()
  - LAPSE+
    - [XML Injection]()
8. XPath 삽입
  - FindBugs
    - [XPATH_INJECTION]()
  - LAPSE+
    - [XPath Injection]()
9. LDAP 삽입
  - 


# Non-KISA GuidLine Bug Pattern
