# KISA GuidLine Bug Pattern
1. SQL 삽입
    - FindBugs
        - [CUSTOM_INJECTION](https://find-sec-bugs.github.io/bugs.htm#CUSTOM_INJECTION)
        - [SQL_INJECTION](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION)
        - [SQL_INJECTION_TURBINE](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_TURBINE)
        - [SQL_INJECTION_HIBERNATE](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_HIBERNATE)
        - [SQL_INJECTION_JDO](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDO)
        - [SQL_INJECTION_JPA](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JPA)
        - [SQL_INJECTION_SPRING_JDBC](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_SPRING_JDBC)
        - [SQL_INJECTION_JDBC](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_JDBC)
        - [SCALA_SQL_INJECTION_SLICK](https://find-sec-bugs.github.io/bugs.htm#SCALA_SQL_INJECTION_SLICK)
        - [SCALA_SQL_INJECTION_ANORM](https://find-sec-bugs.github.io/bugs.htm#SCALA_SQL_INJECTION_ANORM)
        - [SQL_INJECTION_ANDROID](https://find-sec-bugs.github.io/bugs.htm#SQL_INJECTION_ANDROID)
        - [AWS_QUERY_INJECTION](https://find-sec-bugs.github.io/bugs.htm#AWS_QUERY_INJECTION)
        - [SQL: Nonconstant string passed to execute or addBatch method on an SQL statement]()
        - [SQL: A prepared statement is generated from a nonconstant String]()
    - LAPSE+
        - [SQL Injection](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [SQL binding mechanisms should be used]()
2. 경로조작 및 자원삽입
    - FindBugs
        - [PATH_TRAVERSAL_IN](https://find-sec-bugs.github.io/bugs.htm#PATH_TRAVERSAL_IN)
        - [PATH_TRAVERSAL_OUT](https://find-sec-bugs.github.io/bugs.htm#PATH_TRAVERSAL_OU)
        - [SCALA_PATH_TRAVERSAL_IN](https://find-sec-bugs.github.io/bugs.htm#SCALA_PATH_TRAVERSAL_IN)
        - [STRUTS_FILE_DISCLOSURE](https://find-sec-bugs.github.io/bugs.htm#STRUTS_FILE_DISCLOSURE)
        - [SPRING_FILE_DISCLOSURE](https://find-sec-bugs.github.io/bugs.htm#SPRING_FILE_DISCLOSURE)
        - [REQUESTDISPATCHER_FILE_DISCLOSURE](https://find-sec-bugs.github.io/bugs.htm#REQUESTDISPATCHER_FILE_DISCLOSURE)
        - [EXTERNAL_CONFIG_CONTROL](https://find-sec-bugs.github.io/bugs.htm#EXTERNAL_CONFIG_CONTROL)
        - [BEAN_PROPERTY_INJECTION](https://find-sec-bugs.github.io/bugs.htm#BEAN_PROPERTY_INJECTION)
        - [PT: Absolute path traversal in servlet]()
        - [PT: Relative path traversal in servlet]()
    - LAPSE+
        - [Path Traversal](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [Dependencies should not have "system" scope]()
3. 크로스사이트 스크립트
    - FindBugs
        - [XSS_REQUEST_WRAPPER](https://find-sec-bugs.github.io/bugs.htm#XSS_REQUEST_WRAPPER)
        - [JSP_JSTL_OUT](https://find-sec-bugs.github.io/bugs.htm#JSP_JSTL_OUT)
        - [XSS_JSP_PRINT](https://find-sec-bugs.github.io/bugs.htm#XSS_JSP_PRINT)
        - [XSS_SERVLET](https://find-sec-bugs.github.io/bugs.htm#XSS_SERVLET)
        - [ANDROID_GEOLOCATION](https://find-sec-bugs.github.io/bugs.htm#ANDROID_GEOLOCATION)
        - [ANDROID_WEB_VIEW_JAVASCRIPT](https://find-sec-bugs.github.io/bugs.htm#ANDROID_WEB_VIEW_JAVASCRIPT)
        - [ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE](https://find-sec-bugs.github.io/bugs.htm#ANDROID_WEB_VIEW_JAVASCRIPT_INTERFACE)
        - [HTTPONLY_COOKIE](https://find-sec-bugs.github.io/bugs.htm#HTTPONLY_COOKIE)
        - [SCALA_XSS_TWIRL](https://find-sec-bugs.github.io/bugs.htm#SCALA_XSS_TWIRL)
        - [SCALA_XSS_MVC_API](https://find-sec-bugs.github.io/bugs.htm#SCALA_XSS_MVC_API)
        - [XSS: JSP reflected cross site scripting vulnerability]()
        - [XSS: Servlet reflected cross site scripting vulnerability in error page]()
        - [XSS: Servlet reflected cross site scripting vulnerability]()
    - LAPSE+
        - [Cross-Site-Scripting(XSS)](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
4. 운영체제 명령어 삽입
    - FindBugs
        - [COMMAND_INJECTION](https://find-sec-bugs.github.io/bugs.htm#COMMAND_INJECTION)
        - [SCALA_COMMAND_INJECTION](https://find-sec-bugs.github.io/bugs.htm#SCALA_COMMAND_INJECTION)
    - LAPSE+
        - [Command Injection](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [Values passed to OS commands should be sanitized]()
5. 위험한 형식 파일 업로드
    - FindBugs
        - [WEAK_FILENAMEUTILS](https://find-sec-bugs.github.io/bugs.htm#WEAK_FILENAMEUTILS)
        - [FILE_UPLOAD_FILENAME](https://find-sec-bugs.github.io/bugs.htm#FILE_UPLOAD_FILENAME)
6. 신뢰되지 않는 URL 주소로 자동접속 연결
    - FindBugs
        - [UNVALIDATED_REDIRECT](https://find-sec-bugs.github.io/bugs.htm#UNVALIDATED_REDIRECT)
        - [PLAY_UNVALIDATED_REDIRECT](https://find-sec-bugs.github.io/bugs.htm#PLAY_UNVALIDATED_REDIRECT)
        - [SPRING_UNVALIDATED_REDIRECT](https://find-sec-bugs.github.io/bugs.htm#SPRING_UNVALIDATED_REDIRECT)
    - LAPSE+
        - [URL Tampering](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
7. XQuery 삽입
    - FindBugs
        - [XMLStreamReader](https://find-sec-bugs.github.io/bugs.htm#XMLStreamReader)
        - [XXE_SAXPARSER](https://find-sec-bugs.github.io/bugs.htm#XXE_SAXPARSER)
        - [XXE_XMLREADER](https://find-sec-bugs.github.io/bugs.htm#XXE_XMLREADER)
        - [XXE_DOCUMENT](https://find-sec-bugs.github.io/bugs.htm#XXE_DOCUMENT)
        - [XXE_DTD_TRANSFORM_FACTORY](https://find-sec-bugs.github.io/bugs.htm#XXE_DTD_TRANSFORM_FACTORY)
        - [XXE_XSLT_TRANSFORM_FACTORY](https://find-sec-bugs.github.io/bugs.htm#XXE_XSLT_TRANSFORM_FACTORY)
        - [XML_DECODER](https://find-sec-bugs.github.io/bugs.htm#XML_DECODER)
        - [JSP_XSLT](https://find-sec-bugs.github.io/bugs.htm#JSP_XSLT)
        - [MALICIOUS_XSLT](https://find-sec-bugs.github.io/bugs.htm#MALICIOUS_XSLT)
    - LAPSE+
        - [XML Injection](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
8. XPath 삽입
    - FindBugs
        - [XPATH_INJECTION](https://find-sec-bugs.github.io/bugs.htm#XPATH_INJECTION)
    - LAPSE+
        - [XPath Injection](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
9. LDAP 삽입
    - FindBugs
        - [LDAP_INJECTION](https://find-sec-bugs.github.io/bugs.htm#LDAP_INJECTION)
        - [LDAP_ANONYMOUS](https://find-sec-bugs.github.io/bugs.htm#LDAP_ANONYMOUS)
        - [LDAP_ENTRY_POISONING](https://find-sec-bugs.github.io/bugs.htm#LDAP_ENTRY_POISONING)
    - LAPSE+
        - [LDAP Injection](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - [Values passed to LDAP queries should be sanitized.]()
10. 크로스사이트 요청 위조
    - FindBugs
        - [SPRING_CSRF_PROTECTION_DISABLED](https://find-sec-bugs.github.io/bugs.htm#SPRING_CSRF_PROTECTION_DISABLED)
        - [SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING](https://find-sec-bugs.github.io/bugs.htm#SPRING_CSRF_UNRESTRICTED_REQUEST_MAPPING)
    - PMD
        - [NoUnsanitizedJSPExpression]()
11. HTTP 응답분할
    - FindBugs
        - [HTTP_RESPONSE_SPLITTING](https://find-sec-bugs.github.io/bugs.htm#HTTP_RESPONSE_SPLITTING)
        - [HRS: HTTP Response splitting vulnerability]()
    - LAPSE+
        - [Header Manipulation](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
        - [HTTP Response Splitting](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
12. 정수형 오버플로우
13. 보안기능 결정에 사용되는 부적절한 입력값
    - FindBugs
        - [SERVLET_PARAMETER](https://find-sec-bugs.github.io/bugs.htm#SERVLET_PARAMETER)
        - [SERVLET_CONTENT_TYPE](https://find-sec-bugs.github.io/bugs.htm#SERVLET_CONTENT_TYPE)
        - [SERVLET_SERVER_NAME](https://find-sec-bugs.github.io/bugs.htm#SERVLET_SERVER_NAME)
        - [SERVLET_SESSION_ID](https://find-sec-bugs.github.io/bugs.htm#SERVLET_SESSION_ID)
        - [SERVLET_QUERY_STRING](https://find-sec-bugs.github.io/bugs.htm#SERVLET_QUERY_STRING)
        - [SERVLET_HEADER](https://find-sec-bugs.github.io/bugs.htm#SERVLET_HEADER)
        - [SERVLET_HEADER_REFERER](https://find-sec-bugs.github.io/bugs.htm#SERVLET_HEADER_REFERER)
        - [SERVLET_HEADER_USER_AGENT](https://find-sec-bugs.github.io/bugs.htm#SERVLET_HEADER_USER_AGENT)
        - [HTTP_PARAMETER_POLLUTION](https://find-sec-bugs.github.io/bugs.htm#HTTP_PARAMETER_POLLUTION)
    - LAPSE+
        - [Cookie Poisoning](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
        - [Parameter Tampering](https://www.owasp.org/index.php/OWASP_LAPSE_Project)
    - SonarQube
        - ["HttpServletRequest.getRequestedSessionId()" should not be used]()
        - [HTTP referers should not be relied on]()
        - [Untrusted data should not be stored in sessions]()
14. 메모리 버퍼 오버플로우
15. 포멧 스트링 삽입
    - FindBugs
        - [FORMAT_STRING_MANIPULATION](https://find-sec-bugs.github.io/bugs.htm#FORMAT_STRING_MANIPULATION)
16. 적절한 인증 없는 중요기능 허용
17. 부적절한 인가
18. 중요한 자원에 대한 잘못된 권한 설정
19. 취약한 암호화 알고리즘 사용
    - FindBugs
        - [WEAK_MESSAGE_DIGEST_MD5](https://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_MD5)
        - [WEAK_MESSAGE_DIGEST_SHA1](https://find-sec-bugs.github.io/bugs.htm#WEAK_MESSAGE_DIGEST_SHA1)
        - [SSL_CONTEXT](https://find-sec-bugs.github.io/bugs.htm#SSL_CONTEXT)
        - [CUSTOM_MESSAGE_DIGEST](https://find-sec-bugs.github.io/bugs.htm#CUSTOM_MESSAGE_DIGEST)
        - [HAZELCAST_SYMMETRIC_ENCRYPTION](https://find-sec-bugs.github.io/bugs.htm#HAZELCAST_SYMMETRIC_ENCRYPTION)
        - [NULL_CIPHER](https://find-sec-bugs.github.io/bugs.htm#NULL_CIPHER)
        - [DES_USAGE](https://find-sec-bugs.github.io/bugs.htm#DES_USAGE)
        - [TDES_USAGE](https://find-sec-bugs.github.io/bugs.htm#TDES_USAGE)
        - [RSA_NO_PADDING](https://find-sec-bugs.github.io/bugs.htm#RSA_NO_PADDING)
        - [ECB_MODE](https://find-sec-bugs.github.io/bugs.htm#ECB_MODE)
        - [PADDING_ORACLE](https://find-sec-bugs.github.io/bugs.htm#PADDING_ORACLE)
        - [ESAPI_ENCRYPTOR](https://find-sec-bugs.github.io/bugs.htm#ESAPI_ENCRYPTOR)
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
        - [DEFAULT_HTTP_CLIENT](https://find-sec-bugs.github.io/bugs.htm#DEFAULT_HTTP_CLIENT)
        - [UNENCRYPTED_SOCKET](https://find-sec-bugs.github.io/bugs.htm#UNENCRYPTED_SOCKET)
        - [UNENCRYPTED_SERVER_SOCKET](https://find-sec-bugs.github.io/bugs.htm#UNENCRYPTED_SERVER_SOCKET)
        - [INSECURE_COOKIE](https://find-sec-bugs.github.io/bugs.htm#INSECURE_COOKIE)
        - [INSECURE_SMTP_SSL](https://find-sec-bugs.github.io/bugs.htm#INSECURE_SMTP_SSL)
    - SonarQube
        - [Cookies should be “secure”]()
22. 하드코드된 비밀번호
    - FindBugs
        - [HARD_CODE_PASSWORD](https://find-sec-bugs.github.io/bugs.htm#HARD_CODE_PASSWORD)
        - [Dm: Hardcoded constant database password]()
        - [Dm: Empty database password]()
    - SonarQube
        - [Credentials should not be hard-coded]()
23. 충분하지 않은 키 길이 사용
    - FindBugs
        - [BLOWFISH_KEY_SIZE](https://find-sec-bugs.github.io/bugs.htm#BLOWFISH_KEY_SIZE)
        - [RSA_KEY_SIZE](https://find-sec-bugs.github.io/bugs.htm#RSA_KEY_SIZE)
24. 적절하지 않은 난수값 사용
    - FindBugs
        - [PREDICTABLE_RANDOM](https://find-sec-bugs.github.io/bugs.htm#PREDICTABLE_RANDOM)
        - [PREDICTABLE_RANDOM_SCALA](https://find-sec-bugs.github.io/bugs.htm#PREDICTABLE_RANDOM_SCALA)
    - SonarQube
        - ["SecureRandom" seeds should not be predictable]()
25. 취약한 비밀번호 사용
26. 하드코드된 비밀번호 사용
    - FindBugs
        - [HARD_CODE_KEY](https://find-sec-bugs.github.io/bugs.htm#HARD_CODE_KEY)
27. 사용자 하드디스크에 저장되는 쿠키를 통한 정보노출
    - FindBugs
        - [COOKIE_USAGE](https://find-sec-bugs.github.io/bugs.htm#COOKIE_USAGE)
        - [COOKIE_PERSISTENT](https://find-sec-bugs.github.io/bugs.htm#COOKIE_PERSISTENT)
        - [HRS: HTTP cookie formed from untrusted input]()
28. 주석문 안에 포함된 시스템 주요정보
29. 솔트 없이 일방향 해쉬함수 사용
30. 무결성 검사 없는 코드 다운로드
    - FindBugs
        - [JSP_INCLUDE](https://find-sec-bugs.github.io/bugs.htm#JSP_INCLUDE)
    - SonarQube
        - [Classes should not be loaded dynamically]()
31. 반복된 인증시도 제한 기능 부재
32. 경쟁조건: 검사 시점과 사용 시점(TOCTOU)
    - FindBugs
        - [AT: Sequence of calls to concurrent abstraction may not be atomic]()
        - [DC: Possible double check of field]
        - [DC: Possible exposure of partially initialized object]()
        - [DL: Synchronization on Boolean]()
        - [DL: Synchronization on boxed primitive]()
        - [DL: Synchronization on interned String]()
        - [DL: Synchronization on boxed primitive values]()
        - [Dm: Monitor wait() called on Condition]()
        - [Dm: A thread was created using the default empty run method]()
        - [ESync: Empty synchronized block]()
        - [IS: Inconsistent synchronization]()
        - [IS: Field not guarded against concurrent access]()
        - [JLM: Synchronization performed on Lock]()
        - [JLM: Synchronization performed on util.concurrent instance]()
        - [JLM: Using monitor style wait methods on util.concurrent abstraction]()
        - [LI: Incorrect lazy initialization of static field]()
        - [LI: Incorrect lazy initialization and update of static field]()
        - [ML: Synchronization on field in futile attempt to guard that field]()
        - [ML: Method synchronizes on an updated field]()
        - [MWN: Mismatched notify()]()
        - [MWN: Mismatched wait()]()
        - [NN: Naked notify]()
        - [No: Using notify() rather than notifyAll()]()
        - [RS: Class's readObject() method is synchronized]()
        - [RV: Return value of putIfAbsent ignored, value passed to putIfAbsent reused]()
        - [Ru: Invokes run on a thread (did you mean to start it instead?)]()
        - [SC: Constructor invokes Thread.start()]()
        - [SP: Method spins on field]()
        - [STCAL: Call to static Calendar]()
        - [STCAL: Call to static DateFormat]()
        - [STCAL: Static Calendar field]()
        - [STCAL: Static DateFormat]()
        - [SWL: Method calls Thread.sleep() with a lock held]()
        - [TLW: Wait with two locks held]()
        - [UG: Unsynchronized get method, synchronized set method]()
        - [UL: Method does not release lock on all paths]()
        - [UL: Method does not release lock on all exception paths]()
        - [UW: Unconditional wait]()
        - [VO: An increment to a volatile field isn't atomic]()
        - [VO: A volatile reference to an array doesn't treat the array elements as volatile]()
        - [WL: Synchronization on getClass rather than class literal]()
        - [WS: Class's writeObject() method is synchronized but nothing else is]()
        - [Wa: Condition.await() not in loop]()
        - [Wa: Wait not in loop]()
    - PMD
        - [AvoidSynchronizedAtMethodLevel]()
        - [AvoidUsingVolatile]()
        - [DoubleCheckedLocking]()
        - [NonThreadSafeSingleton]()
        - [UnsynchronizedStaticDateFormatter]()
        - [UseConcurrentHashMap]()
    - SonarQube
        - ["wait" should not be called when multiple locks are held]()
        - [Value-based classes should not be used for locking]()
        - ["getClass" should not be used for synchronization]()
        - [Getters and setters should be synchronized in pairs]()
        - [Non-thread-safe fields should not be static]()
        - [Blocks should be synchronized on "private final" fields]()
        - [".equals()" should not be used to test the values of "Atomic" classes]()
        - [Synchronization should not be based on Strings or boxed primitives]()
33. 종료되지 않은 반복문 또는 재귀함수
    - FindBugs
        - [IL: A collection is added to itself]()
        - [IL: An apparent infinite loop]()
        - [IL: An apparent infinite recursive loop]()
    - PMD
        - [EmptyWhileStmt]()
    - SonarQube
        - [Loops should not be infinite]()
        - [Double-checked locking should not be used]()
        - [Locks should be released]()
34. 오류메시지를 통한 정보노출
    - SonarQube
        - [Throwable.printStackTrace(...) should not be called]()
35. 오류 상황 대응 부재
    - PMD
        - [AvoidInstanceofChecksInCatchClause]()
        - [AvoidLiteralsInIfCondition]()
        - [CloneThrowsCloneNotSupportedException]()
        - [DoNotExtendJavaLangThrowable]()
        - [EmptyCatchBlock]()
        - [ReturnFromFinallyBlock]()
    - SonarQube
        - [Exceptions should not be thrown from servlet methods]()
        - ["SingleConnectionFactory" instances should be set to "reconnectOnException"]()
        - ["Iterator.next()" methods should throw "NoSuchElementException"]()
        - [Return values should not be ignored when they contain the operation status code]()
        - [Exception should not be created without being thrown]()
36. 부적절한 예외 처리
    - FindBugs
        - [DE: Method might drop exception]()
        - [DE: Method might ignore exception]()
    - PMD
        - [AvoidCatchingNPE]()
        - [AvoidLosingExceptionInformation]()
        - [UseCorrectExceptionLogging]()
        - [DoNotThrowExceptionInFinally]()
    - SonarQube
        - ["InterruptedException" should not be ignored]()
37. Null Pointer 역참조
    - FindBugs
        - [NP: Method with Boolean return type returns explicit null]()
        - [NP: Clone method may return null]()
        - [NP: equals() method does not check for null argument]()
        - [NP: toString method may return null]()
        - [NP: Null pointer dereference]()
        - [NP: Null pointer dereference in method on exception path]()N
        - [NP: Method does not check for null argument]()
        - [NP: close() invoked on a value that is always null]()
        - [NP: Null value is guaranteed to be dereferenced]()
        - [NP: Value is null and guaranteed to be dereferenced on exception path]()
        - [NP: Non-null field is not initialized]()
        - [NP: Method call passes null to a non-null parameter]()
        - [NP: Method may return null, but is declared @Nonnull]()
        - [NP: A known null value is checked to see if it is an instance of a type]()
        - [NP: Possible null pointer dereference]()
        - [NP: Possible null pointer dereference in method on exception path]()
        - [NP: Method call passes null for non-null parameter]()
        - [NP: Method call passes null for non-null parameter]()
        - [NP: Non-virtual method call passes null for non-null parameter]()
        - [NP: Method with Optional return type returns explicit null]()
        - [NP: Store of null value into field annotated @Nonnull]()
        - [NP: Read of unwritten field]()
        - [NP: Synchronize and null check on the same field]()
    - PMD
        - [BrokenNullCheck]()
        - [MisplacedNullCheck]()
        - [NullAssignment]()
        - [ReturnEmptyArrayRatherThanNull]()
        - [UnusedNullCheckInEquals]()
    - SonarQube
        - [Optional value should only be accessed after calling isPresent()]()
        - ["null" should not be used with "Optional"]()
        - [Null pointers should not be dereferenced]()
        - ["toString()" and "clone()" methods should not return null]()
        - [Constructor injection should be used instead of field injection]()
        - [Short-circuit logic should be used to prevent null pointer dereferences in conditionals]()
38. 부적절한 자원 해제
    - FindBugs
        - [ODR: Method may fail to close database resource]()
        - [ODR: Method may fail to close database resource on exception]()
        - [OS: Method may fail to close stream]()
        - [OS: Method may fail to close stream on exception]()
    - PMD
        - [CloseResource]()
    - SonarQube
        - [Resources should be closed]()
        - [Custom resources should be closed]()
39. 해제된 자원 사용
40. 초기화되지 않은 변수 사용
    - FindBugs
        - [UR: Uninitialized read of field in constructor]()
        - [UR: Uninitialized read of field method called from constructor of superclass]()
    - PMD
        - [DataflowAnomalyAnalysis]()
        - [MissingStaticMethodInNonInstantiatableClass]()
41. 잘못된 세션에 의한 데이터 정보노출
    - FindBugs
        - [MSF: Mutable servlet field]()
    - PMD
        - [StaticEJBFieldShouldBeFinal]()
    - SonarQube
        - [Members of Spring components should be injected]()
        - [Servlets should not have mutable instance fields]()
42. 제거되지 않고 남은 디버그 코드
    - SonarQube
        - [Web applications should not have a "main" method]()
43. 시스템 데이터 정보노출
44. Public 메서드로부터 반환된 Private 배열
    - FindBugs
        - [EI: May expose internal representation by returning reference to mutable object]()
        - [MS: Public static method may expose internal representation by returning array]()
    - SonarQube
        - [Mutable members should not be stored or returned directly]()
45. Private 배열에 Public 데이터 할당
    - FindBugs
        - [EI2: May expose internal representation by incorporating reference to mutable object]()
46. DNS lookup에 의존한 보안결정
47. 취약한 API 
    - FindBugs
        - [Dm: Method invokes System.exit(...)]()
        - [Dm: Method invokes dangerous method runFinalizersOnExit]()
    - PMD
        - [AvoidThreadGroup]()
        - [DoNotUseThreads]()
        - [DontCallThreadRun]()
        - [ProperCloneImplementation]()
        - [UseNotifyAllInsteadOfNotify]()
        - [UseProperClassLoader]()
    - SonarQube
        - ["File.createTempFile" should not be used to create a directory]()
        - [Thread.run() should not be called directly]()
        
# Non-KISA GuidLine Bug Pattern
