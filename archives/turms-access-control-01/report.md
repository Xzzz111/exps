# Turms IM Server - User Online Status Query Broken Access Control Vulnerability

## NAME OF AFFECTED PRODUCT(S)

- **Product**: Turms - Open Source Instant Messaging Engine
- **Vendor Homepage**: https://github.com/turms-im/turms

## AFFECTED AND/OR FIXED VERSION(S)

- **Submitter**: s1ain
- **Affected Version(s)**: Turms v0.10.0-SNAPSHOT and earlier versions
- **Software Link**: https://github.com/turms-im/turms
- **Fixed Version**: Not fixed yet

## PROBLEM TYPE

- **Vulnerability Type**: CWE-284: Improper Access Control / IDOR (Insecure Direct Object Reference)
- **Root Cause**: The `handleQueryUserOnlineStatusesRequest()` method in `UserServiceController.java` contains a TODO comment indicating that access control should be implemented but has not been completed. Any authenticated user can query the online status of arbitrary users without permission validation.
- **Impact**:
  - Privacy violation - Users' online status, device information, and login timestamps can be exposed to unauthorized parties
  - Information disclosure enabling social engineering attacks
  - Ability to track specific users' activity patterns and behaviors

## DESCRIPTION

A broken access control vulnerability exists in Turms instant messaging server's user online status query functionality. The vulnerability allows any authenticated user to query the online status, device type, and login information of any other user in the system without proper authorization checks. The development team has acknowledged this issue through a `// TODO : Access Control` comment in the source code but has not yet implemented the required security controls.

## Code Analysis

**Vulnerable Location**: `turms-service/src/main/java/im/turms/service/domain/user/access/servicerequest/controller/UserServiceController.java:239`

**Vulnerable Code**:
```java
@ServiceRequestMapping(QUERY_USER_ONLINE_STATUSES_REQUEST)
public ClientRequestHandler handleQueryUserOnlineStatusesRequest() {
    return clientRequest -> {
        QueryUserOnlineStatusesRequest request = clientRequest.turmsRequest()
                .getQueryUserOnlineStatusesRequest();
        if (request.getUserIdsCount() == 0) {
            return Mono.empty();
        }
        // TODO : Access Control  ← Access control not implemented!
        List<Long> userIds = request.getUserIdsList();
        int size = userIds.size();
        List<Mono<Pair<Long, UserSessionsStatus>>> monos = new ArrayList<>(size);
        for (Long targetUserId : userIds) {
            monos.add(userStatusService.getUserSessionsStatus(targetUserId)
                    .map(sessionsStatus -> Pair.of(targetUserId, sessionsStatus)));
        }
        return Flux.merge(monos)
                .collect(CollectorUtil.toList(size))
                .map(userIdAndSessionsStatusList -> {
                    // ... returns online status data
                });
    };
}
```

## Authentication Requirements

Authentication is required, but no authorization checks are performed. Any authenticated user can exploit this vulnerability to access other users' online status information.

## Vulnerability Details and POC

**Vulnerability Type**: Broken Access Control / IDOR

**Vulnerability Location**:
- File: `turms-service/src/main/java/im/turms/service/domain/user/access/servicerequest/controller/UserServiceController.java`
- Method: `handleQueryUserOnlineStatusesRequest()`
- Line: 239

**Payload**:

Using Turms client or raw protobuf request:

```protobuf
// User A (ID: 1001) queries User B (ID: 1002) without authorization
TurmsRequest {
  request_id: 123456
  query_user_online_statuses_request: {
    user_ids: [1002, 1003, 1004]  // Can query any user IDs
  }
}
```

**Exploitation Steps**:
1. Authenticate as any valid user (e.g., User A with ID 1001)
2. Send QUERY_USER_ONLINE_STATUSES_REQUEST with arbitrary target user IDs
3. Receive detailed online status information including:
   - Online/offline status
   - Device type (iOS, Android, Web, Desktop)
   - Login timestamp
   - User session details

## Attack Results

Successful exploitation results in:
- Unauthorized disclosure of users' online/offline status
- Exposure of device information and login patterns
- Privacy violation enabling user tracking and profiling
- Potential for targeted social engineering attacks based on online status

## Suggested Repair

1. **Implement relationship-based access control** as indicated by the TODO comment:
```java
// TODO : Access Control  ← Implement this feature
return userRelationshipService
    .areAllRelatedOrFriendsOrInSameGroups(clientRequest.userId(), userIds)
    .flatMap(hasRelationship -> {
        if (!hasRelationship) {
            return Mono.error(new ResponseException(
                ResponseStatusCode.UNAUTHORIZED,
                "Can only query online status of related users"
            ));
        }
        return queryOnlineStatusLogic(userIds);
    });
```

2. **Add configuration option** to control online status visibility:
   - All users
   - Friends only
   - Same group members only
   - Nobody (private mode)

3. **Implement rate limiting** to prevent bulk enumeration of user online statuses

4. **Add audit logging** for online status queries to detect abuse

5. **Security testing** to verify access control implementation before release

## CVSS Score

**CVSS v3.1**: 7.5 (High)
- Attack Vector (AV): Network
- Attack Complexity (AC): Low
- Privileges Required (PR): Low (authenticated user)
- User Interaction (UI): None
- Scope (S): Unchanged
- Confidentiality (C): High
- Integrity (I): None
- Availability (A): None

**Vector String**: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
