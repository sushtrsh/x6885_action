#!/usr/bin/env python3
import os
import sys
import re

path = "system/vold/Decrypt.cpp"
if not os.path.isfile(path):
    print(f"[X6885-Fix] Warning: {path} not found")
    sys.exit(0)

with open(path, "r", encoding="utf-8", errors="ignore") as f:
    content = f.read()

# 1. Remove authToken2AidlVec using if present
content = re.sub(r'using\s+::aidl::android::hardware::security::keymint::km_utils::authToken2AidlVec;\n?', '', content)

# 2. Add null check on keystore
old_ks = "auto keystore = ks2::IKeystoreService::fromBinder(keystoreBinder);"
new_ks = """auto keystore = ks2::IKeystoreService::fromBinder(keystoreBinder);
			if (!keystore) {
				printf("Could not connect to keystore2 service\\n");
				return disk_decryption_secret_key;
			}"""
if old_ks in content and "if (!keystore)" not in content:
    content = content.replace(old_ks, new_ks, 1)
    print("[X6885-Fix] Patched keystore null check")

# 3. Print description on begin_rc failure
content = content.replace('printf("Begin Operation failed\\n");', 'printf("Begin Operation failed: %s\\n", begin_rc.getDescription().c_str());')

# 4. Declare HardwareAuthToken authToken
old_decl = "GKResponse gkResponse;"
new_decl = """GKResponse gkResponse;
			HardwareAuthToken authToken;"""
if old_decl in content and "HardwareAuthToken authToken;" not in content:
    content = content.replace(old_decl, new_decl, 1)
    print("[X6885-Fix] Patched authToken declaration")

# 5. Direct AIDL token extraction from Gatekeeper
old_gk_rsp = "gkResponse = GKResponse::ok(authToken2AidlVec(rsp.hardwareAuthToken));"
new_gk_rsp = """authToken = rsp.hardwareAuthToken;
					gkResponse = GKResponse::ok({});"""
if old_gk_rsp in content:
    content = content.replace(old_gk_rsp, new_gk_rsp)
    print("[X6885-Fix] Patched direct AIDL token extraction")

# 6. Deliver auth token to IKeystoreAuthorization
replacement_dispatch = """\
			if (gkResponse.response_code() != GKResponseCode::OK) {
				printf("Gatekeeper did not verify the credential\\n");
				return Free_Return(retval, weaver_key, &pwd);
			}
			if (!aidl_gk_device) {
				const auto& payload = gkResponse.payload();
				if (payload.size() != sizeof(hw_auth_token_t)) {
					printf("Gatekeeper HIDL returned an invalid auth token size: %zu\\n", payload.size());
					return Free_Return(retval, weaver_key, &pwd);
				}
				hw_auth_token_t hwAuthToken;
				memcpy(&hwAuthToken, payload.data(), sizeof(hwAuthToken));
				authToken.timestamp.milliSeconds = betoh64(hwAuthToken.timestamp);
				authToken.challenge = hwAuthToken.challenge;
				authToken.userId = hwAuthToken.user_id;
				authToken.authenticatorId = hwAuthToken.authenticator_id;
				authToken.authenticatorType = static_cast<HardwareAuthenticatorType>(
						betoh32(hwAuthToken.authenticator_type));
				authToken.mac.assign(&hwAuthToken.hmac[0], &hwAuthToken.hmac[32]);
			}
			if (authToken.mac.size() != 32) {
				printf("Gatekeeper returned an invalid auth token MAC size: %zu\\n", authToken.mac.size());
				return Free_Return(retval, weaver_key, &pwd);
			}
			printf("Gatekeeper auth token ready (authType=%d, MAC bytes=%zu)\\n",
					static_cast<int32_t>(authToken.authenticatorType), authToken.mac.size());
			::ndk::SpAIBinder binder(AServiceManager_getService("android.security.authorization"));
			auto service = aidl::android::security::authorization::IKeystoreAuthorization::fromBinder(binder);
			if (!service) {
				printf("Could not connect to keystore authorization service\\n");
				return Free_Return(retval, weaver_key, &pwd);
			}
			auto binder_result = service->addAuthToken(authToken);
			if (!binder_result.isOk()) {
				printf("Keystore addAuthToken failed: %s\\n", binder_result.getDescription().c_str());
				return Free_Return(retval, weaver_key, &pwd);
			}
			printf("Gatekeeper auth token accepted by keystore\\n");"""

target_pattern = re.compile(r'if\s*\(\s*gkResponse\.response_code\(\)\s*==\s*GKResponseCode::OK\s*\)\s*\{[\s\S]*?auto\s+binder_result\s*=\s*service->addAuthToken\s*\(\s*authToken\s*\);\s*\}\s*\}')
if target_pattern.search(content):
    content = target_pattern.sub(replacement_dispatch, content, count=1)
    print("[X6885-Fix] Patched auth token delivery to IKeystoreAuthorization via regex")
elif "Gatekeeper auth token accepted by keystore" in content:
    print("[X6885-Fix] Auth token delivery already present")
else:
    print("[X6885-Fix] Note: Pattern not matched directly, checking if replacement needed")

with open(path, "w", encoding="utf-8") as f:
    f.write(content)
print("[X6885-Fix] Decrypt.cpp patching step finished.")
