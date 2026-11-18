// Host tests for DNS-SD TXT encoding/decoding, `_airplay._tcp` TXT generation from repo identity,
// and `MdnsAdvertiser` (fake `dns_sd` table, Reactor fd integration, conflict rename, TXT update,
// clean deallocation, and Backend B "unavailable" reporting).

#include "carplay/airplay_info.hpp"
#include "carplay/dnssd_txt.hpp"
#include "carplay/pairing.hpp"
#include "carplay/platform/mdns_advertiser.hpp"
#include "carplay/platform/net_compat.hpp"
#include "carplay/platform/os_random.hpp"
#include "carplay/platform/reactor.hpp"
#include "test_support.hpp"

#include <string.h>

#include <deque>
#include <string>
#include <vector>

struct carplay_DNSServiceRef_t {
    carplay::platform::SocketHandle read_fd;
    carplay::platform::SocketHandle write_fd;
    carplay::platform::DnsServiceRegisterReplyFn callback;
    void* context;
    std::string name;
    std::string regtype;
    std::string domain;
    uint16_t port_be;
    std::vector<uint8_t> txt;
    bool in_process_result;
};

namespace {

namespace dnssd = carplay::dnssd;
namespace info = carplay::info;
namespace pairing = carplay::pairing;
namespace plat = carplay::platform;

struct FakeReply {
    plat::DnsServiceFlags flags;
    plat::DnsServiceErrorType err;
    std::string name;
    std::string regtype;
    std::string domain;
    plat::DnsServiceErrorType process_return_err;

    FakeReply()
        : flags(plat::kDnsServiceFlagsAdd),
          err(plat::kDnsServiceErrNoError),
          process_return_err(plat::kDnsServiceErrNoError) {}
};

struct FakeDnsSdState {
    int register_calls;
    int process_calls;
    int deallocate_calls;
    int update_calls;
    bool deallocated_inside_process;
    plat::DnsServiceErrorType next_register_error;
    bool enable_update_record;
    std::vector<carplay_DNSServiceRef_t*> live_refs;
    carplay_DNSServiceRef_t* last_ref;
    std::string last_registered_name;
    std::string last_registered_regtype;
    uint16_t last_registered_port_be;
    std::vector<uint8_t> last_registered_txt;
    std::vector<uint8_t> last_updated_txt;
    std::deque<FakeReply> queued_replies;

    FakeDnsSdState()
        : register_calls(0),
          process_calls(0),
          deallocate_calls(0),
          update_calls(0),
          deallocated_inside_process(false),
          next_register_error(plat::kDnsServiceErrNoError),
          enable_update_record(true),
          last_ref(NULL),
          last_registered_port_be(0U) {}
};

FakeDnsSdState* g_fake_state = NULL;

plat::DnsServiceErrorType fakeRegister(plat::DnsServiceRef* sdRef,
                                       plat::DnsServiceFlags flags,
                                       uint32_t interfaceIndex,
                                       const char* name,
                                       const char* regtype,
                                       const char* domain,
                                       const char* host,
                                       uint16_t port_be,
                                       uint16_t txtLen,
                                       const void* txtRecord,
                                       plat::DnsServiceRegisterReplyFn callBack,
                                       void* context) {
    (void)flags;
    (void)interfaceIndex;
    (void)host;
    ++g_fake_state->register_calls;
    if (g_fake_state->next_register_error != plat::kDnsServiceErrNoError) {
        return g_fake_state->next_register_error;
    }

    plat::SocketHandle r = plat::kInvalidSocket;
    plat::SocketHandle w = plat::kInvalidSocket;
    if (!plat::wakePairOpen(r, w)) {
        return plat::kDnsServiceErrUnknown;
    }

    carplay_DNSServiceRef_t* ref = new carplay_DNSServiceRef_t();
    ref->read_fd = r;
    ref->write_fd = w;
    ref->callback = callBack;
    ref->context = context;
    ref->name = name != NULL ? name : "";
    ref->regtype = regtype != NULL ? regtype : "";
    ref->domain = domain != NULL ? domain : "local.";
    ref->port_be = port_be;
    if (txtLen > 0U && txtRecord != NULL) {
        const uint8_t* p = static_cast<const uint8_t*>(txtRecord);
        ref->txt.assign(p, p + txtLen);
    }
    ref->in_process_result = false;

    g_fake_state->live_refs.push_back(ref);
    g_fake_state->last_ref = ref;
    g_fake_state->last_registered_name = ref->name;
    g_fake_state->last_registered_regtype = ref->regtype;
    g_fake_state->last_registered_port_be = port_be;
    g_fake_state->last_registered_txt = ref->txt;

    *sdRef = ref;
    return plat::kDnsServiceErrNoError;
}

int fakeRefSockFD(plat::DnsServiceRef sdRef) {
    if (sdRef == NULL) {
        return -1;
    }
    return static_cast<int>(sdRef->read_fd);
}

plat::DnsServiceErrorType fakeProcessResult(plat::DnsServiceRef sdRef) {
    ++g_fake_state->process_calls;
    if (sdRef == NULL) {
        return plat::kDnsServiceErrUnknown;
    }
    plat::wakeDrain(sdRef->read_fd);
    if (g_fake_state->queued_replies.empty()) {
        return plat::kDnsServiceErrNoError;
    }
    const FakeReply rep = g_fake_state->queued_replies.front();
    g_fake_state->queued_replies.pop_front();
    if (rep.process_return_err != plat::kDnsServiceErrNoError) {
        return rep.process_return_err;
    }
    sdRef->in_process_result = true;
    if (sdRef->callback != NULL) {
        sdRef->callback(sdRef, rep.flags, rep.err, rep.name.c_str(), rep.regtype.c_str(),
                        rep.domain.c_str(), sdRef->context);
    }
    sdRef->in_process_result = false;
    return plat::kDnsServiceErrNoError;
}

void fakeRefDeallocate(plat::DnsServiceRef sdRef) {
    ++g_fake_state->deallocate_calls;
    if (sdRef == NULL) {
        return;
    }
    if (sdRef->in_process_result) {
        g_fake_state->deallocated_inside_process = true;
    }
    plat::wakePairClose(sdRef->read_fd, sdRef->write_fd);
    for (size_t i = 0U; i < g_fake_state->live_refs.size(); ++i) {
        if (g_fake_state->live_refs[i] == sdRef) {
            g_fake_state->live_refs.erase(g_fake_state->live_refs.begin() +
                                          static_cast<ptrdiff_t>(i));
            break;
        }
    }
    if (g_fake_state->last_ref == sdRef) {
        g_fake_state->last_ref = NULL;
    }
    delete sdRef;
}

plat::DnsServiceErrorType fakeUpdateRecord(plat::DnsServiceRef sdRef,
                                           void* recordRef,
                                           plat::DnsServiceFlags flags,
                                           uint16_t rdlen,
                                           const void* rdata,
                                           uint32_t ttl) {
    (void)recordRef;
    (void)flags;
    (void)ttl;
    ++g_fake_state->update_calls;
    if (sdRef == NULL) {
        return plat::kDnsServiceErrUnknown;
    }
    g_fake_state->last_updated_txt.clear();
    if (rdlen > 0U && rdata != NULL) {
        const uint8_t* p = static_cast<const uint8_t*>(rdata);
        g_fake_state->last_updated_txt.assign(p, p + rdlen);
    }
    sdRef->txt = g_fake_state->last_updated_txt;
    return plat::kDnsServiceErrNoError;
}

plat::DnsSdApi makeFakeApi(bool with_update) {
    plat::DnsSdApi api;
    api.register_service = &fakeRegister;
    api.ref_sock_fd = &fakeRefSockFD;
    api.process_result = &fakeProcessResult;
    api.ref_deallocate = &fakeRefDeallocate;
    api.update_record = with_update ? &fakeUpdateRecord : NULL;
    return api;
}

void pushReplyAndWake(const FakeReply& rep) {
    g_fake_state->queued_replies.push_back(rep);
    if (g_fake_state->last_ref != NULL) {
        plat::wakeSignal(g_fake_state->last_ref->write_fd);
    }
}

class RecordingMdnsListener : public plat::MdnsAdvertiserListener {
public:
    RecordingMdnsListener() : stopped_count(0) {}

    virtual void onMdnsRegistered(const std::string& assigned_name,
                                  const std::string& regtype,
                                  const std::string& domain) {
        registered.push_back(assigned_name + "|" + regtype + "|" + domain);
    }
    virtual void onMdnsNameConflictRenamed(const std::string& old_name,
                                           const std::string& new_name) {
        renames.push_back(old_name + "->" + new_name);
    }
    virtual void onMdnsError(plat::DnsServiceErrorType code, const std::string& message) {
        (void)message;
        error_codes.push_back(code);
    }
    virtual void onMdnsStopped() { ++stopped_count; }

    std::vector<std::string> registered;
    std::vector<std::string> renames;
    std::vector<plat::DnsServiceErrorType> error_codes;
    int stopped_count;
};

const dnssd::TxtEntry* findEntry(const std::vector<dnssd::TxtEntry>& entries,
                                 const std::string& key) {
    for (size_t i = 0U; i < entries.size(); ++i) {
        if (entries[i].key == key) {
            return &entries[i];
        }
    }
    return NULL;
}

}  // namespace

TEST_CASE(txtRecordEncodingVectorsAndLimits) {
    // Exact wire encoding vector: "k=v1" (len 4) + boolean flag "flg" (len 3).
    dnssd::TxtRecordBuilder b;
    std::string err;
    REQUIRE(b.add("k", "v1", &err));
    REQUIRE(b.addFlag("flg", &err));

    std::vector<uint8_t> wire;
    REQUIRE(b.encode(wire, &err));
    const uint8_t expected[] = {4, 'k', '=', 'v', '1', 3, 'f', 'l', 'g'};
    CHECK_BYTES_EQ(std::vector<uint8_t>(expected, expected + sizeof(expected)), wire);

    std::vector<dnssd::TxtEntry> decoded;
    REQUIRE(dnssd::decodeTxtRecord(wire, decoded, &err));
    REQUIRE(decoded.size() == 2U);
    CHECK_EQ(std::string("k"), decoded[0].key);
    CHECK(decoded[0].has_value);
    CHECK_EQ(std::string("v1"), decoded[0].valueString());
    CHECK_EQ(std::string("flg"), decoded[1].key);
    CHECK(!decoded[1].has_value);

    // Empty record vs DNS TXT RDATA ({0x00}).
    dnssd::TxtRecordBuilder empty_b;
    REQUIRE(empty_b.encode(wire, &err));
    CHECK(wire.empty());
    REQUIRE(empty_b.encodeRdata(wire, &err));
    CHECK_BYTES_EQ(std::vector<uint8_t>(1U, 0x00U), wire);
    REQUIRE(dnssd::decodeTxtRecord(wire, decoded, &err));
    CHECK(decoded.empty());

    // 255-byte boundary: "k=" (2) + 253 bytes = 255 succeeds; 254 fails.
    dnssd::TxtRecordBuilder max_b;
    CHECK(max_b.add("k", std::string(253U, 'x'), &err));
    REQUIRE(max_b.encode(wire, &err));
    CHECK_EQ(static_cast<size_t>(256U), wire.size());
    CHECK_EQ(static_cast<uint8_t>(255U), wire[0]);

    dnssd::TxtRecordBuilder over_b;
    CHECK(!over_b.add("k", std::string(254U, 'x'), &err));

    // Key validation & case-insensitive duplicate rejection.
    CHECK(!dnssd::isValidTxtKey(""));
    CHECK(!dnssd::isValidTxtKey("bad=key"));
    CHECK(!dnssd::isValidTxtKey(std::string("bad\nkey")));
    CHECK(!dnssd::isValidTxtKey(std::string("bad\x7f")));
    CHECK(dnssd::isValidTxtKey("deviceid"));

    dnssd::TxtRecordBuilder dup_b;
    CHECK(dup_b.add("Model", "A", &err));
    CHECK(!dup_b.add("model", "B", &err));

    // Binary value preservation.
    dnssd::TxtRecordBuilder bin_b;
    const uint8_t bin_val[] = {0x00U, 0x01U, 0xffU};
    REQUIRE(bin_b.addBytes("bin", bin_val, sizeof(bin_val), &err));
    REQUIRE(bin_b.encode(wire, &err));
    REQUIRE(dnssd::decodeTxtRecord(wire, decoded, &err));
    REQUIRE(decoded.size() == 1U);
    CHECK_BYTES_EQ(std::vector<uint8_t>(bin_val, bin_val + sizeof(bin_val)), decoded[0].value);
}

TEST_CASE(airplayTxtBuilderFromRepoIdentity) {
    info::AirPlayConfig cfg = info::bmwEntryNav2_800x480(false);
    cfg.device_id = "02:11:22:33:44:55";

    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));

    std::vector<uint8_t> txt_bytes;
    std::string err;
    REQUIRE(dnssd::buildAirPlayTxtRecord(cfg, id, txt_bytes, &err));

    std::vector<dnssd::TxtEntry> entries;
    REQUIRE(dnssd::decodeTxtRecord(txt_bytes, entries, &err));

    const dnssd::TxtEntry* e_dev = findEntry(entries, "deviceid");
    const dnssd::TxtEntry* e_feat = findEntry(entries, "features");
    const dnssd::TxtEntry* e_flags = findEntry(entries, "flags");
    const dnssd::TxtEntry* e_model = findEntry(entries, "model");
    const dnssd::TxtEntry* e_pi = findEntry(entries, "pi");
    const dnssd::TxtEntry* e_pk = findEntry(entries, "pk");
    const dnssd::TxtEntry* e_src = findEntry(entries, "srcvers");

    REQUIRE(e_dev != NULL && e_feat != NULL && e_flags != NULL && e_model != NULL &&
            e_pi != NULL && e_pk != NULL && e_src != NULL);
    CHECK_EQ(std::string("02:11:22:33:44:55"), e_dev->valueString());
    CHECK_EQ(std::string("0x5653aee2,0x61"), e_feat->valueString());
    CHECK_EQ(std::string("0x4"), e_flags->valueString());
    CHECK_EQ(std::string("HU_ENTRYNAV2"), e_model->valueString());
    CHECK_EQ(id.pairing_id, e_pi->valueString());
    CHECK_EQ(test_support::bytesToHex(id.keys.public_key, carplay::crypto::kEd25519PublicKeyBytes),
             e_pk->valueString());
    CHECK_EQ(std::string("950.7.1"), e_src->valueString());

    // Invalid identity or empty config fields fail cleanly.
    pairing::Identity empty_id;
    CHECK(!dnssd::buildAirPlayTxtRecord(cfg, empty_id, txt_bytes, &err));
    info::AirPlayConfig bad_cfg = cfg;
    bad_cfg.device_id.clear();
    CHECK(!dnssd::buildAirPlayTxtRecord(bad_cfg, id, txt_bytes, &err));
}

TEST_CASE(mdnsUnavailableBackendWhenLibraryMissing) {
    // Verified HU_ENTRYNAV2 sysroot order: libdns_sd.so.0 first, then .1, then unversioned .so.
    const std::vector<std::string> defaults = plat::mdnsDefaultLibraryCandidates();
    REQUIRE(defaults.size() == 3U);
    CHECK_EQ(std::string("libdns_sd.so.0"), defaults[0]);
    CHECK_EQ(std::string("libdns_sd.so.1"), defaults[1]);
    CHECK_EQ(std::string("libdns_sd.so"), defaults[2]);

    plat::Reactor reactor;
    REQUIRE(reactor.init());

    // Deterministic dlopen failure test (even on hosts that happen to have libavahi-compat-libdnssd).
    plat::setMdnsLibraryPathsForTest("/nonexistent/libdns_sd.so.0",
                                    "/nonexistent/libdns_sd.so.1",
                                    "/nonexistent/libdns_sd.so");

    plat::MdnsAdvertiser adv(reactor);
    std::string err;
    CHECK(!adv.load(&err));
    CHECK(err.find("libdns_sd.so.0") != std::string::npos);
    CHECK(err.find("libdns_sd.so.1") != std::string::npos);
    CHECK(err.find("/nonexistent/libdns_sd.so") != std::string::npos);
    CHECK_EQ(plat::kMdnsBackendUnavailable, adv.backend());
    CHECK_EQ(std::string("unavailable"), std::string(adv.backendName()));
    CHECK(!adv.available());

    plat::MdnsServiceConfig cfg;
    cfg.service_name = "BMW CarPlay";
    CHECK(!adv.start(cfg, &err));
    CHECK(!adv.isActive());

    // Incomplete API override also reports unavailable cleanly.
    plat::DnsSdApi incomplete;
    incomplete.register_service = &fakeRegister;
    adv.setApiOverride(&incomplete);
    CHECK(!adv.load(&err));
    CHECK_EQ(plat::kMdnsBackendUnavailable, adv.backend());
    CHECK_EQ(std::string("unavailable"), std::string(adv.backendName()));

    plat::setMdnsLibraryPathsForTest(NULL, NULL, NULL);
}

TEST_CASE(mdnsAdvertiserRegisterProcessConflictUpdateDeallocate) {
    FakeDnsSdState state;
    g_fake_state = &state;

    plat::Reactor reactor;
    REQUIRE(reactor.init());

    RecordingMdnsListener listener;
    plat::MdnsAdvertiser adv(reactor);
    adv.setListener(&listener);

    const plat::DnsSdApi api_with_update = makeFakeApi(true);
    adv.setApiOverride(&api_with_update);

    info::AirPlayConfig air_cfg = info::bmwEntryNav2_800x480(false);
    air_cfg.device_id = "02:11:22:33:44:55";
    plat::OsRandomSource rng;
    pairing::Identity id;
    REQUIRE(pairing::generateIdentity(rng, id));

    std::vector<uint8_t> txt;
    std::string err;
    REQUIRE(dnssd::buildAirPlayTxtRecord(air_cfg, id, txt, &err));

    plat::MdnsServiceConfig mcfg;
    mcfg.service_name = "BMW CarPlay";
    mcfg.port = 7000U;
    mcfg.txt_record = txt;

    REQUIRE(adv.start(mcfg, &err));
    CHECK(adv.isActive());
    CHECK_EQ(plat::kMdnsBackendDnsSd, adv.backend());
    CHECK_EQ(1, state.register_calls);
    CHECK_EQ(std::string("BMW CarPlay"), state.last_registered_name);
    CHECK_EQ(std::string("_airplay._tcp"), state.last_registered_regtype);
    CHECK_BYTES_EQ(txt, state.last_registered_txt);

    // Port 7000 (0x1b58) must be passed in network byte order (big-endian).
    uint8_t port_bytes[2];
    memcpy(port_bytes, &state.last_registered_port_be, 2U);
    CHECK_EQ(static_cast<uint8_t>(0x1bU), port_bytes[0]);
    CHECK_EQ(static_cast<uint8_t>(0x58U), port_bytes[1]);

    // Simulate registration reply via Reactor wakeup.
    FakeReply ok_rep;
    ok_rep.err = plat::kDnsServiceErrNoError;
    ok_rep.name = "BMW CarPlay";
    ok_rep.regtype = "_airplay._tcp";
    ok_rep.domain = "local.";
    pushReplyAndWake(ok_rep);
    reactor.runOnce(50);

    CHECK_EQ(1, state.process_calls);
    CHECK(adv.isRegistered());
    CHECK_EQ(std::string("BMW CarPlay"), adv.assignedName());
    REQUIRE(listener.registered.size() == 1U);
    CHECK_EQ(std::string("BMW CarPlay|_airplay._tcp|local."), listener.registered[0]);
    CHECK(listener.renames.empty());

    // Update TXT record via DNSServiceUpdateRecord.
    dnssd::TxtRecordBuilder updated_b;
    REQUIRE(updated_b.add("deviceid", "02:11:22:33:44:66", &err));
    std::vector<uint8_t> txt2;
    REQUIRE(updated_b.encode(txt2, &err));
    REQUIRE(adv.updateTxtRecord(txt2, &err));
    CHECK_EQ(1, state.update_calls);
    CHECK_BYTES_EQ(txt2, state.last_updated_txt);

    // Case 1 conflict: mdnsd auto-renames and delivers NoError with new name.
    FakeReply auto_rename_rep;
    auto_rename_rep.err = plat::kDnsServiceErrNoError;
    auto_rename_rep.name = "BMW CarPlay (2)";
    auto_rename_rep.regtype = "_airplay._tcp";
    auto_rename_rep.domain = "local.";
    pushReplyAndWake(auto_rename_rep);
    reactor.runOnce(50);

    CHECK_EQ(std::string("BMW CarPlay (2)"), adv.assignedName());
    REQUIRE(listener.renames.size() == 1U);
    CHECK_EQ(std::string("BMW CarPlay->BMW CarPlay (2)"), listener.renames[0]);

    // Stop deallocates cleanly without leaving live refs.
    adv.stop();
    CHECK(!adv.isActive());
    CHECK(!adv.isRegistered());
    CHECK_EQ(1, state.deallocate_calls);
    CHECK_EQ(1, listener.stopped_count);
    CHECK(state.live_refs.empty());

    // Case 2 conflict: explicit kDnsServiceErrNameConflict triggers safe post-ProcessResult
    // deallocation and re-registration with " (2)" suffix, then confirmation.
    const plat::DnsSdApi api_no_update = makeFakeApi(false);
    adv.setApiOverride(&api_no_update);
    listener = RecordingMdnsListener();
    mcfg.allow_auto_rename = false;
    REQUIRE(adv.start(mcfg, &err));
    const int reg_before = state.register_calls;
    const int dealloc_before = state.deallocate_calls;

    FakeReply conflict_rep;
    conflict_rep.err = plat::kDnsServiceErrNameConflict;
    conflict_rep.name = "BMW CarPlay";
    conflict_rep.regtype = "_airplay._tcp";
    conflict_rep.domain = "local.";
    pushReplyAndWake(conflict_rep);
    reactor.runOnce(50);

    CHECK(!state.deallocated_inside_process);
    CHECK_EQ(dealloc_before + 1, state.deallocate_calls);
    CHECK_EQ(reg_before + 1, state.register_calls);
    CHECK_EQ(1, adv.conflictRetryCount());
    CHECK_EQ(std::string("BMW CarPlay (2)"), state.last_registered_name);

    FakeReply retry_ok_rep;
    retry_ok_rep.err = plat::kDnsServiceErrNoError;
    retry_ok_rep.name = "BMW CarPlay (2)";
    retry_ok_rep.regtype = "_airplay._tcp";
    retry_ok_rep.domain = "local.";
    pushReplyAndWake(retry_ok_rep);
    reactor.runOnce(50);

    CHECK(adv.isRegistered());
    CHECK_EQ(std::string("BMW CarPlay (2)"), adv.assignedName());
    REQUIRE(listener.renames.size() == 1U);
    CHECK_EQ(std::string("BMW CarPlay->BMW CarPlay (2)"), listener.renames[0]);

    // Update TXT without DNSServiceUpdateRecord falls back to deallocate + re-register.
    REQUIRE(adv.updateTxtRecord(txt, &err));
    CHECK_EQ(reg_before + 2, state.register_calls);
    CHECK_BYTES_EQ(txt, state.last_registered_txt);

    adv.stop();
    CHECK(state.live_refs.empty());
    g_fake_state = NULL;
}

int main() {
    return test_support::runAll("test_mdns_advertiser");
}
