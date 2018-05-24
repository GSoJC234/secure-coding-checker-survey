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
    - FindBugs
        - [LDAP_INJECTION]()
        - [LDAP_ANONYMOUS]()
        - [LDAP_ENTRY_POISONING]()
    - LAPSE+
        - [LDAP Injection]()
    - SonarQube
        - [Values passed to LDAP queries should be sanitized.]()
10. 크로스사이트 요청 위조
    - FindBugs
        - [SPRING_CSRF_PROTECTION_DISABLED]()
        - [SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING]()
    - PMD
        - [NoUnsanitizedJSPExpression]()
11. HTTP 응답분할
    - FindBugs
        - [HTTP_RESPONSE_SPLITTING]()
        - [HRS: HTTP Response splitting vulnerability]()
    - LAPSE+
        - [Header Manipulation]()
        - [HTTP Response Splitting]()
12. 정수형 오버플로우
13. 보안기능 결정에 사용되는 부적절한 입력값
    - FindBugs
        - [SERVLET_PARAMETER]()
        - [SERVLET_CONTENT_TYPE]()
        - [SERVLET_SERVER_NAME]()
        - [SERVLET_SESSION_ID]()
        - [SERVLET_QUERY_STRING]()
        - [SERVLET_HEADER]()
        - [SERVLET_HEADER_REFERER]()
        - [SERVLET_HEADER_USER_AGENT]()
        - [HTTP_PARAMETER_POLLUTION]()
    - LAPSE+
        - [Cookie Poisoning]()
        - [Parameter Tampering]()
    - SonarQube
        - ["HttpServletRequest.getRequestedSessionId()" should not be used]()
        - [HTTP referers should not be relied on]()
        - [Untrusted data should not be stored in sessions]()
14. 메모리 버퍼 오버플로우
15. 포멧 스트링 삽입
    - FindBugs
        - [FORMAT_STRING_MANIPULATION]()
16. 적절한 인증 없는 중요기능 허용
17. 부적절한 인가
18. 중요한 자원에 대한 잘못된 권한 설정
19. 취약한 암호화 알고리즘 사용
    - FindBugs
        - [WEAK_MESSAGE_DIGEST_MD5]()
        - [WEAK_MESSAGE_DIGEST_SHA1]()
        - [SSL_CONTEXT]()
        - [CUSTOM_MESSAGE_DIGEST]()
        - [HAZELCAST_SYMMETRIC_ENCRYPTION]()
        - [NULL_CIPHER]()
        - [DES_USAGE]()
        - [TDES_USAGE]()
        - [RSA_NO_PADDING]()
        - [ECB_MODE]()
        - [PADDING_ORACLE]()
        - [ESAPI_ENCRYPTOR]()
    - SonarQube
        - [Neither DES (Data Encryption Standard) nor DESede (3DES) should be used]()
        - [Cryptographic RSA algorithms should always incorporate OAEP (Optimal Asymmetric Encryption Padding)]()
        - ["javax.crypto.NullCipher" should not be used for anything other than testing]()
        - [Only standard cryptographic algorithms should be used]()
        - [Pseudorandom number generators (PRNGs) should not be used in secure contexts]()
        - [SHA-1 and Message-Digest hash algorithms should not be used]()
20. 중요정보 평문 저장
21. 중요정보 평문 전송
    - FindBugs
        - [DEFAULT_HTTP_CLIENT]()
        - [UNENCRYPTED_SOCKET]()
        - [UNENCRYPTED_SERVER_SOCKET]()
        - [INSECURE_COOKIE]()
        - [INSECURE_SMTP_SSL]()
    - SonarQube
        - [Cookies should be “secure”]()
22. 하드코드된 비밀번호
    - FindBugs
        - [HARD_CODE_PASSWORD]()
        - [Dm: Hardcoded constant database password]()
        - [Dm: Empty database password]()
    - SonarQube
        - [Credentials should not be hard-coded]()
23. 충분하지 않은 키 길이 사용
    - FindBugs
        - [BLOWFISH_KEY_SIZE]()
        - [RSA_KEY_SIZE]()
24. 적절하지 않은 난수값 사용
    - FindBugs
        - [PREDICTABLE_RANDOM]()
        - [PREDICTABLE_RANDOM_SCALA]()
    - SonarQube
        - ["SecureRandom" seeds should not be predictable]()
25. 취약한 비밀번호 사용
26. 하드코드된 비밀번호 사용
    - FindBugs
        - [HARD_CODE_KEY]()
27. 사용자 하드디스크에 저장되는 쿠키를 통한 정보노출
    - FindBugs
        - [COOKIE_USAGE]()
        - [COOKIE_PERSISTENT]()
        - [HRS: HTTP cookie formed from untrusted input]()
28. 주석문 안에 포함된 시스템 주요정보
29. 솔트 없이 일방향 해쉬함수 사용
30. 무결성 검사 없는 코드 다운로드
    - FindBugs
        - [JSP_INCLUDE]()
    - SonarQube
        - [Classes should not be loaded dynamically]()
31. 반복된 인증시도 제한 기능 부재
32. 경쟁조건: 검사 시점과 사용 시점(TOCTOU)



# Non-KISA GuidLine Bug Pattern
