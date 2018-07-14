# KISA GuidLine Bug Pattern
1. SQL 삽입
    - FindBugs
        - [CUSTOM_INJECTION [1]](https://find-sec-bugs.github.io/bugs.htm#CUSTOM_INJECTION)
        - [SQL_INJECTION [2]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION)
        - [SQL_INJECTION_TURBINE [3]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_TURBINE)
        - [SQL_INJECTION_HIBERNATE [4]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_HIBERNATE)
        - [SQL_INJECTION_JDO [5]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDO)
        - [SQL_INJECTION_JPA [6]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JPA)
        - [SQL_INJECTION_SPRING_JDBC [7]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_SPRING_JDBC)
        - [SQL_INJECTION_JDBC [8]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC)
        - [SCALA_SQL_INJECTION_SLICK [9]](https://find-sec-bugs.github.io/bugs.htm#SCALA_SQL_INJECTION_SLICK)
        - [SCALA_SQL_INJECTION_ANORM [10]](https://find-sec-bugs.github.io/bugs.htm#SCALA_SQL_INJECTION_ANORM)
        - [SQL_INJECTION_ANDROID [11]](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_ANDROID)
        - [AWS_QUERY_INJECTION [12]](https://find-sec-bugs.github.io/bugs.htm#AWS_QUERY_INJECTION)
        - [SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE [13]](http://findbugs.sourceforge.net/bugDescriptions.html#SQL_NONCONSTANT_STRING_PASSED_TO_EXECUTE)
        - [SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING [14]](http://findbugs.sourceforge.net/bugDescriptions.html#SQL_PREPARED_STATEMENT_GENERATED_FROM_NONCONSTANT_STRING)
    - LAPSE+
        - [SQL Injection [2]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [SQL binding mechanisms should be used [14]](https://rules.sonarsource.com/java/RSPEC-2077)
2. 경로조작 및 자원삽입
    - FindBugs
        - [PATH_TRAVERSAL_IN [1]](https://find-sec-bugs.github.io/bugs.htm#PATH_TRAVERSAL_IN)
        - [PATH_TRAVERSAL_OUT [2]](https://find-sec-bugs.github.io/bugs.htm#PATH_TRAVERSAL_OU)
        - [SCALA_PATH_TRAVERSAL_IN [3]](https://find-sec-bugs.github.io/bugs.htm#SCALA_PATH_TRAVERSAL_IN)
        - [STRUTS_FILE_DISCLOSURE [4]](https://find-sec-bugs.github.io/bugs.htm#STRUTS_FILE_DISCLOSURE)
        - [SPRING_FILE_DISCLOSURE [5]](https://find-sec-bugs.github.io/bugs.htm#SPRING_FILE_DISCLOSURE)
        - [REQUESTDISPATCHER_FILE_DISCLOSURE [6]](https://find-sec-bugs.github.io/bugs.htm#REQUESTDISPATCHER_FILE_DISCLOSURE)
        - [EXTERNAL_CONFIG_CONTROL [7]](https://find-sec-bugs.github.io/bugs.htm#EXTERNAL_CONFIG_CONTROL)
        - [BEAN_PROPERTY_INJECTION [8]](https://find-sec-bugs.github.io/bugs.htm#BEAN_PROPERTY_INJECTION)
        - [PT_ABSOLUTE_PATH_TRAVERSAL [9]](http://findbugs.sourceforge.net/bugDescriptions.html#PT_ABSOLUTE_PATH_TRAVERSAL)
        - [PT_RELATIVE_PATH_TRAVERSAL [10]](http://findbugs.sourceforge.net/bugDescriptions.html#PT_RELATIVE_PATH_TRAVERSAL)
    - LAPSE+
        - [Path Traversal [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [Dependencies should not have "system" scope [11]](https://rules.sonarsource.com/java/RSPEC-3422)
3. 크로스사이트 스크립트
    - FindBugs
        - [XSS_REQUEST_WRAPPER [1]](https://find-sec-bugs.github.io/bugs.htm#XSS_REQUEST_WRAPPER)
        - [JSP_JSTL_OUT [2]](https://find-sec-bugs.github.io/bugs.htm#JSP_JSTL_OUT)
        - [XSS_JSP_PRINT [3]](https://find-sec-bugs.github.io/bugs.htm#XSS_JSP_PRINT)
        - [XSS_SERVLET [4]](https://find-sec-bugs.github.io/bugs.htm#XSS_SERVLET)
        - [ANDROID_GEOLOCATION [5]](https://find-sec-bugs.github.io/bugs.htm#ANDROID_GEOLOCATION)
        - [ANDROID_WEB_VIEW_JAVASCRIPT [6]](https://find-sec-bugs.github.io/bugs.htm#ANDROID_WEB_VIEW_JAVASCRIPT)
        - [ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE [7]](https://find-sec-bugs.github.io/bugs.htm#ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE)
        - [HTTPONLY_COOKIE [8]](https://find-sec-bugs.github.io/bugs.htm#HTTPONLY_COOKIE)
        - [SCALA_XSS_TWIRL [9]](https://find-sec-bugs.github.io/bugs.htm#SCALA_XSS_TWIRL)
        - [SCALA_XSS_MVC_API [10]](https://find-sec-bugs.github.io/bugs.htm#SCALA_XSS_MVC_API)
        - [XSS_REQUEST_PARAMETER_TO_JSP_WRITER [11]](http://findbugs.sourceforge.net/bugDescriptions.html#XSS_REQUEST_PARAMETER_TO_JSP_WRITER)
        - [XSS_REQUEST_PARAMETER_TO_SEND_ERROR [12]](http://findbugs.sourceforge.net/bugDescriptions.html#XSS_REQUEST_PARAMETER_TO_SEND_ERROR)
        - [XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER [13]](http://findbugs.sourceforge.net/bugDescriptions.html#XSS_REQUEST_PARAMETER_TO_SERVLET_WRITER)
    - LAPSE+
        - [Cross-Site-Scripting(XSS) [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
4. 운영체제 명령어 삽입
    - FindBugs
        - [COMMAND_INJECTION [1]](https://find-sec-bugs.github.io/bugs.htm#COMMAND_INJECTION)
        - [SCALA_COMMAND_INJECTION [2]](https://find-sec-bugs.github.io/bugs.htm#SCALA_COMMAND_INJECTION)
    - LAPSE+
        - [Command Injection [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [Values passed to OS commands should be sanitized [1]](https://rules.sonarsource.com/java/RSPEC-2076)
5. 위험한 형식 파일 업로드
    - FindBugs
        - [WEAK_FILENAMEUTILS [1]](https://find-sec-bugs.github.io/bugs.htm#WEAK_FILENAMEUTILS)
        - [FILE_UPLOAD_FILENAME [2]](https://find-sec-bugs.github.io/bugs.htm#FILE_UPLOAD_FILENAME)
6. 신뢰되지 않는 URL 주소로 자동접속 연결
    - FindBugs
        - [UNVALIDATED_REDIRECT [1]](https://find-sec-bugs.github.io/bugs.htm#UNVALIDATED_REDIRECT)
        - [PLAY_UNVALIDATED_REDIRECT [2]](https://find-sec-bugs.github.io/bugs.htm#PLAY_UNVALIDATED_REDIRECT)
        - [SPRING_UNVALIDATED_REDIRECT [3]](https://find-sec-bugs.github.io/bugs.htm#SPRING_UNVALIDATED_REDIRECT)
    - LAPSE+
        - [URL Tampering [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
7. XQuery 삽입
    - FindBugs
        - [XMLStreamReader [1]](https://find-sec-bugs.github.io/bugs.htm#XMLStreamReader)
        - [XXE_SAXPARSER [2]](https://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER)
        - [XXE_XMLREADER [3]](https://find-sec-bugs.github.io/bugs.htm#XXE_XMLREADER)
        - [XXE_DOCUMENT [4]](https://find-sec-bugs.github.io/bugs.htm#XXE_DOCUMENT)
        - [XXE_DTD_TRANSFORM_FACTORY [5]](https://find-sec-bugs.github.io/bugs.htm#XXE_DTD_TRANSFORM_FACTORY)
        - [XXE_XSLT_TRANSFORM_FACTORY [6]](https://find-sec-bugs.github.io/bugs.htm#XXE_XSLT_TRANSFORM_FACTORY)
        - [XML_DECODER [7]](https://find-sec-bugs.github.io/bugs.htm#XML_DECODER)
        - [JSP_XSLT [8]](https://find-sec-bugs.github.io/bugs.htm#JSP_XSLT)
        - [MALICIOUS_XSLT [9]](https://find-sec-bugs.github.io/bugs.htm#MALICIOUS_XSLT)
    - LAPSE+
        - [XML Injection [4]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
8. XPath 삽입
    - FindBugs
        - [XPATH_INJECTION [1]](https://find-sec-bugs.github.io/bugs.htm#XPATH_INJECTION)
    - LAPSE+
        - [XPath Injection [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
9. LDAP 삽입
    - FindBugs
        - [LDAP_INJECTION [1]](https://find-sec-bugs.github.io/bugs.htm#LDAP_INJECTION)
        - [LDAP_ANONYMOUS [2]](https://find-sec-bugs.github.io/bugs.htm#LDAP_ANONYMOUS)
        - [LDAP_ENTRY_POISONING [3]](https://find-sec-bugs.github.io/bugs.htm#LDAP_ENTRY_POISONING)
    - LAPSE+
        - [LDAP Injection [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [Values passed to LDAP queries should be sanitized [1]](https://rules.sonarsource.com/java/RSPEC-2078)
10. 크로스사이트 요청 위조 [Extended]
    - FindBugs
        - [SPRING_CSRF_PROTECTION_DISABLED [1]](https://find-sec-bugs.github.io/bugs.htm#SPRING_CSRF_PROTECTION_DISABLED)
        - [SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING [2]](https://find-sec-bugs.github.io/bugs.htm#SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING)
        - [SCALA_PLAY_SSRF [3]](https://find-sec-bugs.github.io/bugs.htm#SCALA_PLAY_SSRF)
        - [URLCONNECTION_SSRF_FD [4]](https://find-sec-bugs.github.io/bugs.htm#URLCONNECTION_SSRF_FD)
    - PMD
        - [NoUnsanitizedJSPExpression [5]](https://pmd.github.io/pmd-6.3.0/pmd_rules_jsp_security.html#nounsanitizedjspexpression)
11. HTTP 응답분할
    - FindBugs
        - [HTTP_RESPONSE_SPLITTING [1]](https://find-sec-bugs.github.io/bugs.htm#HTTP_RESPONSE_SPLITTING)
        - [HRS_REQUEST_PARAMETER_TO_HTTP_HEADER [2]](http://findbugs.sourceforge.net/bugDescriptions.html#HRS_REQUEST_PARAMETER_TO_HTTP_HEADER)
    - LAPSE+
        - [Header Manipulation [2]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
        - [HTTP Response Splitting [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
12. 정수형 오버플로우 [Extended]
    - FindBugs
        - [BAD_HEXA_CONVERSION [1]](https://find-sec-bugs.github.io/bugs.htm#BAD_HEXA_CONVERSION)
    - PMD
        - [BadComparison [2]](https://pmd.github.io/pmd-6.4.0/pmd_rules_java_errorprone.html#badcomparison)
    - SonarQube
        - ["Double.longBitsToDouble" should not be used for "int" [3]](https://rules.sonarsource.com/java/RSPEC-2127)
    
13. 보안기능 결정에 사용되는 부적절한 입력값 [Extended]
    - FindBugs
        - [SERVLET_PARAMETER [1]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_PARAMETER)
        - [SERVLET_CONTENT_TYPE [2]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_CONTENT_TYPE)
        - [SERVLET_SERVER_NAME [3]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_SERVER_NAME)
        - [SERVLET_SESSION_ID [4]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_SESSION_ID)
        - [SERVLET_QUERY_STRING [5]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_QUERY_STRING)
        - [SERVLET_HEADER [6]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_HEADER)
        - [SERVLET_HEADER_REFERER [7]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_HEADER_REFERER)
        - [SERVLET_HEADER_USER_AGENT [8]](https://find-sec-bugs.github.io/bugs.htm#SERVLET_HEADER_USER_AGENT)
        - [HTTP_PARAMETER_POLLUTION [9]](https://find-sec-bugs.github.io/bugs.htm#HTTP_PARAMETER_POLLUTION)
        - [TRUST_BOUNDARY_VIOLATION [12]](https://find-sec-bugs.github.io/bugs.htm#TRUST_BOUNDARY_VIOLATION)
    - LAPSE+
        - [Cookie Poisoning [10]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
        - [Parameter Tampering [1]](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - ["HttpServletRequest.getRequestedSessionId()" should not be used [4]](https://rules.sonarsource.com/java/RSPEC-2254)
        - [HTTP referers should not be relied on [7]](https://rules.sonarsource.com/java/RSPEC-2089)
        - [Untrusted data should not be stored in sessions [11]](https://rules.sonarsource.com/java/RSPEC-3318)
15. 포멧 스트링 삽입
    - FindBugs
        - [FORMAT_STRING_MANIPULATION [1]](https://find-sec-bugs.github.io/bugs.htm#FORMAT_STRING_MANIPULATION)
16. 적절한 인증 없는 중요기능 허용
17. 부적절한 인가
18. 중요한 자원에 대한 잘못된 권한 설정
19. 취약한 암호화 알고리즘 사용 [Extended]
    - FindBugs
        - [WEAK_MESSAGE_DIGEST_MD5 [1]](https://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_MD5)
        - [WEAK_MESSAGE_DIGEST_SHA1 [2]](https://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_SHA1)
        - [SSL_CONTEXT [3]](https://find-sec-bugs.github.io/bugs.htm#SSL_CONTEXT)
        - [CUSTOM_MESSAGE_DIGEST [4]](https://find-sec-bugs.github.io/bugs.htm#CUSTOM_MESSAGE_DIGEST)
        - [HAZELCAST_SYMMETRIC_ENCRYPTION [5]](https://find-sec-bugs.github.io/bugs.htm#HAZELCAST_SYMMETRIC_ENCRYPTION)
        - [NULL_CIPHER [6]](https://find-sec-bugs.github.io/bugs.htm#NULL_CIPHER)
        - [DES_USAGE [7]](https://find-sec-bugs.github.io/bugs.htm#DES_USAGE)
        - [TDES_USAGE [8]](https://find-sec-bugs.github.io/bugs.htm#TDES_USAGE)
        - [RSA_NO_PADDING [9]](https://find-sec-bugs.github.io/bugs.htm#RSA_NO_PADDING)
        - [ECB_MODE [10]](https://find-sec-bugs.github.io/bugs.htm#ECB_MODE)
        - [PADDING_ORACLE [11]](https://find-sec-bugs.github.io/bugs.htm#PADDING_ORACLE)
        - [ESAPI_ENCRYPTOR [12]](https://find-sec-bugs.github.io/bugs.htm#ESAPI_ENCRYPTOR)
        - [CIPHER_INTEGRITY [15]](https://find-sec-bugs.github.io/bugs.htm#CIPHER_INTEGRITY )
    - SonarQube
        - [Neither DES (Data Encryption Standard) nor DESede (3DES) should be used [7]](https://rules.sonarsource.com/java/RSPEC-2278)
        - [Cryptographic RSA algorithms should always incorporate OAEP (Optimal Asymmetric Encryption Padding) [13]](https://rules.sonarsource.com/java/RSPEC-2277)
        - ["javax.crypto.NullCipher" should not be used for anything other than testing [6]](https://rules.sonarsource.com/java/RSPEC-2258)
        - [Only standard cryptographic algorithms should be used [4]](https://rules.sonarsource.com/java/RSPEC-2257)
        - [Pseudorandom number generators (PRNGs) should not be used in secure contexts [14]](https://rules.sonarsource.com/java/RSPEC-2245)
        - [SHA-1 and Message-Digest hash algorithms should not be used [2]](https://rules.sonarsource.com/java/RSPEC-2070)
20. 중요정보 평문 저장
21. 중요정보 평문 전송 [Extended]
    - FindBugs
        - [DEFAULT_HTTP_CLIENT [1]](https://find-sec-bugs.github.io/bugs.htm#DEFAULT_HTTP_CLIENT)
        - [UNENCRYPTED_SOCKET [2]](https://find-sec-bugs.github.io/bugs.htm#UNENCRYPTED_SOCKET)
        - [UNENCRYPTED_SERVER_SOCKET [3]](https://find-sec-bugs.github.io/bugs.htm#UNENCRYPTED_SERVER_SOCKET)
        - [INSECURE_COOKIE [4]](https://find-sec-bugs.github.io/bugs.htm#INSECURE_COOKIE)
        - [INSECURE_SMTP_SSL [5]](https://find-sec-bugs.github.io/bugs.htm#INSECURE_SMTP_SSL)
        - [URL_REWRITING [6]](https://find-sec-bugs.github.io/bugs.htm#URL_REWRITING)
    - SonarQube
        - [Cookies should be “secure” [4]](https://rules.sonarsource.com/java/RSPEC-2092)
22. 하드코드된 비밀번호
    - FindBugs
        - [HARD_CODE_PASSWORD [1]](https://find-sec-bugs.github.io/bugs.htm#HARD_CODE_PASSWORD)
        - [DMI_CONSTANT_DB_PASSWORD [2]](http://findbugs.sourceforge.net/bugDescriptions.html#DMI_CONSTANT_DB_PASSWORD)
        - [DMI_EMPTY_DB_PASSWORD [3]](http://findbugs.sourceforge.net/bugDescriptions.html#DMI_EMPTY_DB_PASSWORD)
    - SonarQube
        - [Credentials should not be hard-coded [2]](https://rules.sonarsource.com/java/RSPEC-2068)
23. 충분하지 않은 키 길이 사용
    - FindBugs
        - [BLOWFISH_KEY_SIZE [1]](https://find-sec-bugs.github.io/bugs.htm#BLOWFISH_KEY_SIZE)
        - [RSA_KEY_SIZE [2]](https://find-sec-bugs.github.io/bugs.htm#RSA_KEY_SIZE)
24. 적절하지 않은 난수값 사용
    - FindBugs
        - [PREDICTABLE_RANDOM [1]](https://find-sec-bugs.github.io/bugs.htm#PREDICTABLE_RANDOM)
        - [PREDICTABLE_RANDOM_SCALA [2]](https://find-sec-bugs.github.io/bugs.htm#PREDICTABLE_RANDOM_SCALA)
    - SonarQube
        - ["SecureRandom" seeds should not be predictable [3]](https://rules.sonarsource.com/java/RSPEC-4347)
25. 취약한 비밀번호 사용
26. 하드코드된 암호화 키 [Extended]
    - FindBugs
        - [HARD_CODE_KEY [1]](https://find-sec-bugs.github.io/bugs.htm#HARD_CODE_KEY)
    - SonarQube
        - [IP addresses should not be hardcoded [2]]()
27. 사용자 하드디스크에 저장되는 쿠키를 통한 정보노출
    - FindBugs
        - [COOKIE_USAGE [1]](https://find-sec-bugs.github.io/bugs.htm#COOKIE_USAGE)
        - [COOKIE_PERSISTENT [2]](https://find-sec-bugs.github.io/bugs.htm#COOKIE_PERSISTENT)
        - [HRS_REQUEST_PARAMETER_TO_COOKIE [3]](http://findbugs.sourceforge.net/bugDescriptions.html#HRS_REQUEST_PARAMETER_TO_COOKIE)
28. 주석문 안에 포함된 시스템 주요정보
29. 솔트 없이 일방향 해쉬함수 사용
30. 무결성 검사 없는 코드 다운로드
    - FindBugs
        - [JSP_INCLUDE [1]](https://find-sec-bugs.github.io/bugs.htm#JSP_INCLUDE)
    - SonarQube
        - [Classes should not be loaded dynamically [2]](https://rules.sonarsource.com/java/RSPEC-2658)
31. 반복된 인증시도 제한 기능 부재
32. 경쟁조건: 검사 시점과 사용 시점(TOCTOU)
    - FindBugs
        - [AT_OPERATION_SEQUENCE_ON_CONCURRENT_ABSTRACTION [1]](http://findbugs.sourceforge.net/bugDescriptions.html#AT_OPERATION_SEQUENCE_ON_CONCURRENT_ABSTRACTION)
        - [DC_DOUBLECHECK [2]](http://findbugs.sourceforge.net/bugDescriptions.html#DC_DOUBLECHECK)
        - [DC_PARTIALLY_CONSTRUCTED [3]](http://findbugs.sourceforge.net/bugDescriptions.html#DC_PARTIALLY_CONSTRUCTED)
        - [DL_SYNCHRONIZATION_ON_BOOLEAN [4]](http://findbugs.sourceforge.net/bugDescriptions.html#DL_SYNCHRONIZATION_ON_BOOLEAN)
        - [DL_SYNCHRONIZATION_ON_UNSHARED_BOXED_PRIMITIVE [5]](http://findbugs.sourceforge.net/bugDescriptions.html#DL_SYNCHRONIZATION_ON_UNSHARED_BOXED_PRIMITIVE)
        - [DL_SYNCHRONIZATION_ON_SHARED_CONSTANT [6]](http://findbugs.sourceforge.net/bugDescriptions.html#DL_SYNCHRONIZATION_ON_SHARED_CONSTANT)
        - [DL_SYNCHRONIZATION_ON_UNSHARED_BOXED_PRIMITIVE [7]](http://findbugs.sourceforge.net/bugDescriptions.html#DL_SYNCHRONIZATION_ON_UNSHARED_BOXED_PRIMITIVE)
        - [DM_MONITOR_WAIT_ON_CONDITION [8]](http://findbugs.sourceforge.net/bugDescriptions.html#DM_MONITOR_WAIT_ON_CONDITION)
        - [DM_USELESS_THREAD [9]](http://findbugs.sourceforge.net/bugDescriptions.html#DM_USELESS_THREAD)
        - [ESync_EMPTY_SYNC [10]](http://findbugs.sourceforge.net/bugDescriptions.html#ESync_EMPTY_SYNC)
        - [IS2_INCONSISTENT_SYNC [11]](http://findbugs.sourceforge.net/bugDescriptions.html#IS2_INCONSISTENT_SYNC)
        - [IS_FIELD_NOT_GUARDED [12]](http://findbugs.sourceforge.net/bugDescriptions.html#IS_FIELD_NOT_GUARDED)
        - [JLM_JSR166_LOCK_MONITORENTER [13]](http://findbugs.sourceforge.net/bugDescriptions.html#JLM_JSR166_LOCK_MONITORENTER)
        - [JLM_JSR166_UTILCONCURRENT_MONITORENTER [14]](http://findbugs.sourceforge.net/bugDescriptions.html#JLM_JSR166_UTILCONCURRENT_MONITORENTER)
        - [JML_JSR166_CALLING_WAIT_RATHER_THAN_AWAIT [15]](http://findbugs.sourceforge.net/bugDescriptions.html#JML_JSR166_CALLING_WAIT_RATHER_THAN_AWAIT)
        - [LI_LAZY_INIT_STATIC [16]](http://findbugs.sourceforge.net/bugDescriptions.html#LI_LAZY_INIT_STATIC)
        - [LI_LAZY_INIT_UPDATE_STATIC [17]](http://findbugs.sourceforge.net/bugDescriptions.html#LI_LAZY_INIT_UPDATE_STATIC)
        - [ML_SYNC_ON_FIELD_TO_GUARD_CHANGING_THAT_FIELD [18]](http://findbugs.sourceforge.net/bugDescriptions.html#ML_SYNC_ON_FIELD_TO_GUARD_CHANGING_THAT_FIELD)
        - [ML_SYNC_ON_UPDATED_FIELD [19]](http://findbugs.sourceforge.net/bugDescriptions.html#ML_SYNC_ON_UPDATED_FIELD)
        - [MWN_MISMATCHED_NOTIFY [20]](http://findbugs.sourceforge.net/bugDescriptions.html#MWN_MISMATCHED_NOTIFY)
        - [MWN_MISMATCHED_WAIT [21]](http://findbugs.sourceforge.net/bugDescriptions.html#MWN_MISMATCHED_WAIT)
        - [NN_NAKED_NOTIFY [22]](http://findbugs.sourceforge.net/bugDescriptions.html#NN_NAKED_NOTIFY)
        - [NO_NOTIFY_NOT_NOTIFYALL [23]](http://findbugs.sourceforge.net/bugDescriptions.html#NO_NOTIFY_NOT_NOTIFYALL)
        - [RS_READOBJECT_SYNC [24]](http://findbugs.sourceforge.net/bugDescriptions.html#RS_READOBJECT_SYNC)
        - [RV_RETURN_VALUE_OF_PUTIFABSENT_IGNORED [25]](http://findbugs.sourceforge.net/bugDescriptions.html#RV_RETURN_VALUE_OF_PUTIFABSENT_IGNORED)
        - [RU_INVOKE_RUN [26]](http://findbugs.sourceforge.net/bugDescriptions.html#RU_INVOKE_RUN)
        - [SC_START_IN_CTOR [27]](http://findbugs.sourceforge.net/bugDescriptions.html#SC_START_IN_CTOR)
        - [SP_SPIN_ON_FIELD [28]](http://findbugs.sourceforge.net/bugDescriptions.html#SP_SPIN_ON_FIELD)
        - [STCAL_INVOKE_ON_STATIC_CALENDAR_INSTANCE [29]](http://findbugs.sourceforge.net/bugDescriptions.html#STCAL_INVOKE_ON_STATIC_CALENDAR_INSTANCE)
        - [STCAL_INVOKE_ON_STATIC_DATE_FORMAT_INSTANCE [30]](http://findbugs.sourceforge.net/bugDescriptions.html#STCAL_INVOKE_ON_STATIC_DATE_FORMAT_INSTANCE)
        - [STCAL_STATIC_CALENDAR_INSTANCE [31]](http://findbugs.sourceforge.net/bugDescriptions.html#STCAL_STATIC_CALENDAR_INSTANCE)
        - [STCAL_STATIC_SIMPLE_DATE_FORMAT_INSTANCE [32]](http://findbugs.sourceforge.net/bugDescriptions.html#STCAL_STATIC_SIMPLE_DATE_FORMAT_INSTANCE)
        - [SWL_SLEEP_WITH_LOCK_HELD [33]](http://findbugs.sourceforge.net/bugDescriptions.html#SWL_SLEEP_WITH_LOCK_HELD)
        - [TLW_TWO_LOCK_WAIT [34]](http://findbugs.sourceforge.net/bugDescriptions.html#TLW_TWO_LOCK_WAIT)
        - [UG_SYNC_SET_UNSYNC_GET [35]](http://findbugs.sourceforge.net/bugDescriptions.html#UG_SYNC_SET_UNSYNC_GET)
        - [UL_UNRELEASED_LOCK [36]](http://findbugs.sourceforge.net/bugDescriptions.html#UL_UNRELEASED_LOCK)
        - [UL_UNRELEASED_LOCK_EXCEPTION_PATH [37]](http://findbugs.sourceforge.net/bugDescriptions.html#UL_UNRELEASED_LOCK_EXCEPTION_PATH)
        - [UW_UNCOND_WAIT [38]](http://findbugs.sourceforge.net/bugDescriptions.html#UW_UNCOND_WAIT)
        - [VO_VOLATILE_INCREMENT [39]](http://findbugs.sourceforge.net/bugDescriptions.html#VO_VOLATILE_INCREMENT)
        - [VO_VOLATILE_REFERENCE_TO_ARRAY [40]](http://findbugs.sourceforge.net/bugDescriptions.html#VO_VOLATILE_REFERENCE_TO_ARRAY)
        - [WL_USING_GETCLASS_RATHER_THANODR_OPEN_DATABASE_RESOURCE_EXCEPTION_PATH_CLASS_LITERAL [41]](http://findbugs.sourceforge.net/bugDescriptions.html#WL_USING_GETCLASS_RATHER_THAN_CLASS_LITERAL)
        - [WS_WRITEOBJECT_SYNC [42]](http://findbugs.sourceforge.net/bugDescriptions.html#WS_WRITEOBJECT_SYNC)
        - [WA_AWAIT_NOT_IN_LOOP [43]](http://findbugs.sourceforge.net/bugDescriptions.html#WA_AWAIT_NOT_IN_LOOP)
        - [WA_NOT_IN_LOOP [44]](http://findbugs.sourceforge.net/bugDescriptions.html#WA_NOT_IN_LOOP)
    - PMD
        - [AvoidSynchronizedAtMethodLevel [45]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#avoidsynchronizedatmethodlevel)
        - [AvoidUsingVolatile [46]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#avoidusingvolatile)
        - [DoubleCheckedLocking [47]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#doublecheckedlocking)
        - [NonThreadSafeSingleton [48]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#nonthreadsafesingleton)
        - [UnsynchronizedStaticDateFormatter [49]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#unsynchronizedstaticdateformatter)
        - [UseConcurrentHashMap [49]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#useconcurrenthashmap)
    - SonarQube
        - ["wait" should not be called when multiple locks are held [34]](https://rules.sonarsource.com/java/RSPEC-3046)
        - [Value-based classes should not be used for locking [50]](https://rules.sonarsource.com/java/RSPEC-3436)
        - ["getClass" should not be used for synchronization [51]](https://rules.sonarsource.com/java/RSPEC-3067)
        - [Getters and setters should be synchronized in pairs [52]](https://rules.sonarsource.com/java/RSPEC-2886)
        - [Non-thread-safe fields should not be static [53]](https://rules.sonarsource.com/java/RSPEC-2885)
        - [Blocks should be synchronized on "private final" fields [57]](https://rules.sonarsource.com/java/RSPEC-2445)
        - [".equals()" should not be used to test the values of "Atomic" classes [58]](https://rules.sonarsource.com/java/RSPEC-2204)
        - [Synchronization should not be based on Strings or boxed primitives [59]](https://rules.sonarsource.com/java/RSPEC-1860)
33. 종료되지 않은 반복문 또는 재귀함수
    - FindBugs
        - [IL_CONTAINER_ADDED_TO_ITSELF [1]](http://findbugs.sourceforge.net/bugDescriptions.html#IL_CONTAINER_ADDED_TO_ITSELF)
        - [IL_INFINITE_LOOP [2]](http://findbugs.sourceforge.net/bugDescriptions.html#IL_INFINITE_LOOP)
        - [IL_INFINITE_RECURSIVE_LOOP [3]](http://findbugs.sourceforge.net/bugDescriptions.html#IL_INFINITE_RECURSIVE_LOOP)
    - PMD
        - [EmptyWhileStmt [4]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#emptywhilestmt)
    - SonarQube
        - [Loops should not be infinite [2]](https://rules.sonarsource.com/java/RSPEC-2189)
        - [Double-checked locking should not be used [5]](https://rules.sonarsource.com/java/RSPEC-2168)
        - [Locks should be released [6]](https://rules.sonarsource.com/java/RSPEC-2222)
34. 오류메시지를 통한 정보노출
    - SonarQube
        - [Throwable.printStackTrace(...) should not be called [1]](https://rules.sonarsource.com/java/RSPEC-1148)
35. 오류 상황 대응 부재
    - PMD
        - [AvoidInstanceofChecksInCatchClause [1]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#avoidinstanceofchecksincatchclause)
        - [AvoidLiteralsInIfCondition [2]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#avoidliteralsinifcondition)
        - [CloneThrowsCloneNotSupportedException [3]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#clonethrowsclonenotsupportedexception)
        - [DoNotExtendJavaLangThrowable [4]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#donotextendjavalangthrowable)
        - [EmptyCatchBlock [5]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#emptycatchblock)
        - [ReturnFromFinallyBlock [6]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#returnfromfinallyblock)
    - SonarQube
        - [Exceptions should not be thrown from servlet methods [7]](https://rules.sonarsource.com/java/RSPEC-1989)
        - ["SingleConnectionFactory" instances should be set to "reconnectOnException" [8]](https://rules.sonarsource.com/java/RSPEC-3438)
        - ["Iterator.next()" methods should throw "NoSuchElementException" [9]](https://rules.sonarsource.com/java/RSPEC-2272)
        - [Return values should not be ignored when they contain the operation status code [10]](https://rules.sonarsource.com/java/RSPEC-899)
        - [Exception should not be created without being thrown [11]](https://rules.sonarsource.com/java/RSPEC-3984)
36. 부적절한 예외 처리
    - FindBugs
        - [DE_MIGHT_DROP [1]](http://findbugs.sourceforge.net/bugDescriptions.html#DE_MIGHT_DROP)
        - [DE_MIGHT_IGNORE [2]](http://findbugs.sourceforge.net/bugDescriptions.html#DE_MIGHT_IGNORE)
    - PMD
        - [AvoidCatchingNPE [2]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#avoidcatchingnpe)
        - [AvoidLosingExceptionInformation [2]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#avoidlosingexceptioninformation)
        - [UseCorrectExceptionLogging [3]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#usecorrectexceptionlogging)
        - [DoNotThrowExceptionInFinally [4]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#donotthrowexceptioninfinally)
    - SonarQube
        - ["InterruptedException" should not be ignored [2]](https://rules.sonarsource.com/java/RSPEC-2142)
37. 잘못된 세션에 의한 데이터 정보노출
    - FindBugs
        - [MSF_MUTABLE_SERVLET_FIELD [1]](http://findbugs.sourceforge.net/bugDescriptions.html#MSF_MUTABLE_SERVLET_FIELD)
    - PMD
        - [StaticEJBFieldShouldBeFinal [2]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#staticejbfieldshouldbefinal)
    - SonarQube
        - [Members of Spring components should be injected [3]](https://rules.sonarsource.com/java/RSPEC-3749)
        - [Servlets should not have mutable instance fields [1]](https://rules.sonarsource.com/java/RSPEC-2226)
38. 제거되지 않고 남은 디버그 코드
    - SonarQube
        - [Web applications should not have a "main" method [1]](https://rules.sonarsource.com/java/RSPEC-2653)
39. 시스템 데이터 정보노출
40. Public 메서드로부터 반환된 Private 배열
    - FindBugs
        - [EI_EXPOSE_REP [1]](http://findbugs.sourceforge.net/bugDescriptions.html#EI_EXPOSE_REP)
        - [MS_EXPOSE_REP [2]](http://findbugs.sourceforge.net/bugDescriptions.html#MS_EXPOSE_REP)
    - SonarQube
        - [Mutable members should not be stored or returned directly [1]](https://rules.sonarsource.com/java/RSPEC-2384)
41. Private 배열에 Public 데이터 할당
    - FindBugs
        - [EI_EXPOSE_REP2 [1]](http://findbugs.sourceforge.net/bugDescriptions.html#EI_EXPOSE_REP2)
42. DNS lookup에 의존한 보안결정
43. 취약한 API 
    - FindBugs
        - [DM_EXIT [1]](http://findbugs.sourceforge.net/bugDescriptions.html#DM_EXIT)
        - [DM_RUN_FINALIZERS_ON_EXIT [2]](http://findbugs.sourceforge.net/bugDescriptions.html#DM_RUN_FINALIZERS_ON_EXIT)
    - PMD
        - [AvoidThreadGroup [3]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#avoidthreadgroup)
        - [DoNotUseThreads [4]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#donotusethreads)
        - [DontCallThreadRun [5]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#dontcallthreadrun)
        - [ProperCloneImplementation [6]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#propercloneimplementation)
        - [UseNotifyAllInsteadOfNotify [7]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_multithreading.html#usenotifyallinsteadofnotify)
        - [UseProperClassLoader [8]](https://pmd.github.io/pmd-6.3.0/pmd_rules_java_errorprone.html#useproperclassloader)
    - SonarQube
        - ["File.createTempFile" should not be used to create a directory [9]](https://rules.sonarsource.com/java/RSPEC-2976)
        - [Thread.run() should not be called directly [5]](https://rules.sonarsource.com/java/RSPEC-1217)
        
# Non-KISA GuidLine Bug Pattern
1. 암호화 방식의 잘못된 사용
    - FindBugs
        - [WEAK_TRUST_MANAGER [1]](https://find-sec-bugs.github.io/bugs.htm#WEAK_TRUST_MANAGER)
        - [WEAK_HOSTNAME_VERIFIER [2]](https://find-sec-bugs.github.io/bugs.htm#WEAK_HOSTNAME_VERIFIER)
        - [STATIC_IV [3]](https://find-sec-bugs.github.io/bugs.htm#STATIC_IV)
        - [UNSAFE_HASH_EQUALS [4]](https://find-sec-bugs.github.io/bugs.htm#UNSAFE_HASH_EQUALS)
2. 프레임워크의 고유한 프로그래밍 규칙 위반
    - FindBugs
        - [JAXWS_ENDPOINT [1]](https://find-sec-bugs.github.io/bugs.htm#JAXWS_ENDPOINT)
        - [JAXRS_ENDPOINT [2]](https://find-sec-bugs.github.io/bugs.htm#JAXRS_ENDPOINT)
        - [TAPESTRY_ENDPOINT [3]](https://find-sec-bugs.github.io/bugs.htm#TAPESTRY_ENDPOINT)
        - [WICKET_ENDPOINT [4]](https://find-sec-bugs.github.io/bugs.htm#WICKET_ENDPOINT)
        - [STRUTS1_ENDPOINT [5]](https://find-sec-bugs.github.io/bugs.htm#STRUTS1_ENDPOINT)
        - [STRUTS2_ENDPOINT [6]](https://find-sec-bugs.github.io/bugs.htm#STRUTS2_ENDPOINT)
        - [SPRING_ENDPOINT [7]](https://find-sec-bugs.github.io/bugs.htm#SPRING_ENDPOINT)
        - [STRUTS_FORM_VALIDATION [8]](https://find-sec-bugs.github.io/bugs.htm#STRUTS_FORM_VALIDATION)
        - [ANDROID_BROADCAST [9]](https://find-sec-bugs.github.io/bugs.htm#ANDROID_BROADCAST)
        - [ANDROID_WORLD_WRITABLE [10]](https://find-sec-bugs.github.io/bugs.htm#ANDROID_WORLD_WRITABLE)
        - [PERMISSIVE_CORS [11]](https://find-sec-bugs.github.io/bugs.htm#PERMISSIVE_CORS)
        - [ANDROID_EXTERNAL_FILE_ACCESS [12]](https://find-sec-bugs.github.io/bugs.htm#ANDROID_EXTERNAL_FILE_ACCESS)
        - [SCALA_SENSITIVE_DATA_EXPOSURE [13]](https://find-sec-bugs.github.io/bugs.htm#SCALA_SENSITIVE_DATA_EXPOSURE)
    - SonarQube
        - [Default EJB interceptors should be declared in "ejb-jar.xml [14]](https://rules.sonarsource.com/java/RSPEC-3281)
        - [Defined filters should be used [15]](https://rules.sonarsource.com/java/RSPEC-3355)
        - ["@RequestMapping" methods should be "public" [16]](https://rules.sonarsource.com/java/RSPEC-3751)
        - [Struts validation forms should have unique names [17]](https://rules.sonarsource.com/java/RSPEC-3374)
        - [Security constraints should be defined [18]](https://rules.sonarsource.com/java/RSPEC-3369)
        - [Non-public methods should not be "@Transactional" [19]](https://rules.sonarsource.com/java/RSPEC-2230)
3. 자원부족을 일으킬 수 있는 명령 허용
    - FindBugs
        - [ReDOS [1]](https://find-sec-bugs.github.io/bugs.htm#ReDOS)
    - SonarQube
        - [Inappropriate regular expressions should not be used [2]](https://rules.sonarsource.com/java/RSPEC-2639)
        - [The value returned from a stream read should be checked [3]](https://rules.sonarsource.com/java/RSPEC-2674)
4. 코드 삽입
    - FindBugs
        - [SCRIPT_ENGINE_INJECTION [1]](https://find-sec-bugs.github.io/bugs.htm#SCRIPT_ENGINE_INJECTION)
        - [SPEL_INJECTION [2]](https://find-sec-bugs.github.io/bugs.htm#SPEL_INJECTION)
        - [EL_INJECTION [3]](https://find-sec-bugs.github.io/bugs.htm#EL_INJECTION)
        - [OGNL_INJECTION [4]](https://find-sec-bugs.github.io/bugs.htm#OGNL_INJECTION)
        - [JSP_SPRING_EVAL [5]](https://find-sec-bugs.github.io/bugs.htm#JSP_SPRING_EVAL)
        - [OBJECT_DESERIALIZATION [6]](https://find-sec-bugs.github.io/bugs.htm#OBJECT_DESERIALIZATION)
        - [JACKSON_UNSAFE_DESERIALIZATION [7]](https://find-sec-bugs.github.io/bugs.htm#JACKSON_UNSAFE_DESERIALIZATION)
        - [DESERIALIZATION_GADGET [8]](https://find-sec-bugs.github.io/bugs.htm#DESERIALIZATION_GADGET)
        - [TEMPLATE_INJECTION_VELOCITY [9]](https://find-sec-bugs.github.io/bugs.htm#TEMPLATE_INJECTION_VELOCITY)
        - [TEMPLATE_INJECTION_FREEMARKER [10]](https://find-sec-bugs.github.io/bugs.htm#TEMPLATE_INJECTION_FREEMARKER)
5. 로그 삽입
    - FindBugs
        - [SEAM_LOG_INJECTION [1]](https://find-sec-bugs.github.io/bugs.htm#SEAM_LOG_INJECTION)
        - [CRLF_INJECTION_LOGS [2]](https://find-sec-bugs.github.io/bugs.htm#CRLF_INJECTION_LOGS)

    
