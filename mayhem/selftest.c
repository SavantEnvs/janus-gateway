/* Known-answer tests for the Janus RTP/RTCP/SDP helpers the fuzz harnesses exercise.
 * Built by mayhem/build.sh with the project's normal flags and run by mayhem/test.sh. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <glib.h>
#include "../src/debug.h"
#include "../src/utils.h"
#include "../src/rtp.h"
#include "../src/rtcp.h"
#include "../src/sdp-utils.h"

int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;
int refcount_debug = 0;

int RAND_bytes(uint8_t *key, int len) {
	memset(key, 0, len);
	return 1;
}

static int total = 0, failed = 0;

#define CHECK(name, cond) do { \
	total++; \
	if(cond) { printf("PASS %s\n", name); } \
	else { failed++; printf("FAIL %s (line %d)\n", name, __LINE__); } \
} while(0)

static const char *offer_sdp =
	"v=0\r\n"
	"o=- 4611731400430051336 2 IN IP4 127.0.0.1\r\n"
	"s=-\r\n"
	"t=0 0\r\n"
	"a=group:BUNDLE 0 1\r\n"
	"m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n"
	"c=IN IP4 0.0.0.0\r\n"
	"a=mid:0\r\n"
	"a=sendonly\r\n"
	"a=rtpmap:111 opus/48000/2\r\n"
	"a=fmtp:111 minptime=10;useinbandfec=1\r\n"
	"a=rtpmap:0 PCMU/8000\r\n"
	"m=video 9 UDP/TLS/RTP/SAVPF 96 98\r\n"
	"c=IN IP4 0.0.0.0\r\n"
	"a=mid:1\r\n"
	"a=recvonly\r\n"
	"a=rtpmap:96 VP8/90000\r\n"
	"a=rtpmap:98 H264/90000\r\n"
	"a=fmtp:98 profile-level-id=42e01f;packetization-mode=1\r\n";

static void test_sdp(void) {
	char err[512] = { 0 };
	janus_sdp *sdp = janus_sdp_parse(offer_sdp, err, sizeof(err));
	CHECK("sdp.parse", sdp != NULL);
	if(sdp == NULL)
		return;
	CHECK("sdp.session_id", sdp->o_sessid == 4611731400430051336ULL);
	CHECK("sdp.audio_pt_opus", janus_sdp_get_codec_pt(sdp, 0, "opus") == 111);
	CHECK("sdp.audio_pt_pcmu", janus_sdp_get_codec_pt(sdp, 0, "pcmu") == 0);
	CHECK("sdp.video_pt_vp8", janus_sdp_get_codec_pt(sdp, 1, "vp8") == 96);
	CHECK("sdp.video_pt_h264", janus_sdp_get_codec_pt(sdp, 1, "h264") == 98);
	CHECK("sdp.missing_codec", janus_sdp_get_codec_pt(sdp, 0, "vp9") < 0);
	const char *name = janus_sdp_get_codec_name(sdp, 1, 98);
	CHECK("sdp.codec_name", name != NULL && !strcasecmp(name, "h264"));
	const char *fmtp = janus_sdp_get_fmtp(sdp, 0, 111);
	CHECK("sdp.fmtp", fmtp != NULL && !strcmp(fmtp, "minptime=10;useinbandfec=1"));
	janus_sdp_mline *audio = janus_sdp_mline_find(sdp, JANUS_SDP_AUDIO);
	CHECK("sdp.audio_mline", audio != NULL && audio->direction == JANUS_SDP_SENDONLY);
	janus_sdp_mline *video = janus_sdp_mline_find(sdp, JANUS_SDP_VIDEO);
	CHECK("sdp.video_mline", video != NULL && video->direction == JANUS_SDP_RECVONLY);
	CHECK("sdp.no_application", janus_sdp_mline_find(sdp, JANUS_SDP_APPLICATION) == NULL);

	char *written = janus_sdp_write(sdp);
	CHECK("sdp.write_rtpmap", written != NULL && strstr(written, "a=rtpmap:111 opus/48000/2") != NULL);
	CHECK("sdp.write_mline", written != NULL && strstr(written, "m=video 9 UDP/TLS/RTP/SAVPF 96 98") != NULL);
	janus_sdp *again = written ? janus_sdp_parse(written, err, sizeof(err)) : NULL;
	CHECK("sdp.roundtrip", again != NULL && janus_sdp_get_codec_pt(again, 1, "h264") == 98);
	char *written2 = again ? janus_sdp_write(again) : NULL;
	CHECK("sdp.roundtrip_stable", written != NULL && written2 != NULL && !strcmp(written, written2));
	g_free(written2);
	janus_sdp_destroy(again);
	g_free(written);

	CHECK("sdp.remove_pt", janus_sdp_remove_payload_type(sdp, 0, 0) == 0 && janus_sdp_get_codec_pt(sdp, 0, "pcmu") < 0);
	CHECK("sdp.mline_remove", janus_sdp_mline_remove(sdp, JANUS_SDP_VIDEO) == 0 && janus_sdp_mline_find(sdp, JANUS_SDP_VIDEO) == NULL);
	janus_sdp_destroy(sdp);

	CHECK("sdp.reject_garbage", janus_sdp_parse("this is not an sdp", err, sizeof(err)) == NULL);
	CHECK("sdp.reject_missing_version", janus_sdp_parse("s=-\r\nt=0 0\r\n", err, sizeof(err)) == NULL);
	CHECK("sdp.mtype_str", !strcmp(janus_sdp_mtype_str(JANUS_SDP_VIDEO), "video"));
	CHECK("sdp.mdirection_parse", janus_sdp_parse_mdirection("inactive") == JANUS_SDP_INACTIVE);
}

static void test_rtp(void) {
	/* V=2, no padding/extension/CSRC, M=0, PT=96, seq=0x1234, ts=0x01020304, ssrc=0xCAFEBABE, payload "abc" */
	char plain[15] = { (char)0x80, 96, 0x12, 0x34, 0x01, 0x02, 0x03, 0x04,
		(char)0xCA, (char)0xFE, (char)0xBA, (char)0xBE, 'a', 'b', 'c' };
	CHECK("rtp.is_rtp", janus_is_rtp(plain, sizeof(plain)));
	CHECK("rtp.reject_short", !janus_is_rtp(plain, 8));
	/* Payload types 64-95 (7-bit) collide with RTCP packet types and are demultiplexed away from RTP */
	char notrtp[15];
	memcpy(notrtp, plain, sizeof(notrtp));
	notrtp[1] = 72;
	CHECK("rtp.reject_rtcp_range", !janus_is_rtp(notrtp, sizeof(notrtp)));
	int plen = -1;
	char *payload = janus_rtp_payload(plain, sizeof(plain), &plen);
	CHECK("rtp.payload_offset", payload == plain + 12 && plen == 3);
	CHECK("rtp.payload_bytes", payload != NULL && !memcmp(payload, "abc", 3));
	janus_rtp_header *hdr = (janus_rtp_header *)plain;
	CHECK("rtp.header_fields", hdr->version == 2 && hdr->type == 96 && ntohs(hdr->seq_number) == 0x1234 &&
		ntohl(hdr->ssrc) == 0xCAFEBABE);

	/* Same packet with a one-byte header extension (0xBEDE, 1 word): id=1 audio-level (vad=1, level=40),
	 * then id=2 mid "m1", then padding */
	char ext[12 + 4 + 8 + 3] = { (char)0x90, 111, 0x00, 0x07, 0, 0, 0, 1, 0, 0, 0, 2,
		(char)0xBE, (char)0xDE, 0x00, 0x02,
		0x10, (char)(0x80 | 40), 0x21, 'm', '1', 0, 0, 0,
		'x', 'y', 'z' };
	CHECK("rtp.ext_is_rtp", janus_is_rtp(ext, sizeof(ext)));
	gboolean vad = FALSE;
	int level = -1;
	CHECK("rtp.audio_level_found", janus_rtp_header_extension_parse_audio_level(ext, sizeof(ext), 1, &vad, &level) == 0);
	CHECK("rtp.audio_level_values", vad == TRUE && level == 40);
	CHECK("rtp.audio_level_wrong_id", janus_rtp_header_extension_parse_audio_level(ext, sizeof(ext), 5, &vad, &level) < 0);
	char mid[16] = { 0 };
	CHECK("rtp.mid_found", janus_rtp_header_extension_parse_mid(ext, sizeof(ext), 2, mid, sizeof(mid)) == 0);
	CHECK("rtp.mid_value", !strcmp(mid, "m1"));
	payload = janus_rtp_payload(ext, sizeof(ext), &plen);
	CHECK("rtp.ext_payload", payload == ext + 24 && plen == 3 && !memcmp(payload, "xyz", 3));
	CHECK("rtp.replace_id", janus_rtp_header_extension_replace_id(ext, sizeof(ext), 2, 7) == 0 &&
		((uint8_t)ext[18] >> 4) == 7 &&
		janus_rtp_header_extension_parse_mid(ext, sizeof(ext), 7, mid, sizeof(mid)) == 0);
	CHECK("rtp.replace_id_missing", janus_rtp_header_extension_replace_id(ext, sizeof(ext), 9, 3) < 0);
	/* Extension length claims more words than the packet holds: must be rejected */
	char trunc[16] = { (char)0x90, 111, 0, 1, 0, 0, 0, 1, 0, 0, 0, 2, (char)0xBE, (char)0xDE, 0x00, 0x20 };
	CHECK("rtp.truncated_ext_payload", janus_rtp_payload(trunc, sizeof(trunc), &plen) == NULL);

	/* VP8: keyframe has bit 0 of the frame tag clear and the 9d 01 2a start code */
	char vp8key[20] = { 0x10, 0x00, 0x00, 0x00, (char)0x9d, 0x01, 0x2a };
	char vp8inter[20] = { 0x10, 0x01, 0x00, 0x00, (char)0x9d, 0x01, 0x2a };
	CHECK("vp8.keyframe", janus_vp8_is_keyframe(vp8key, sizeof(vp8key)));
	CHECK("vp8.interframe", !janus_vp8_is_keyframe(vp8inter, sizeof(vp8inter)));
	/* H.264: STAP-A carrying an SPS (NAL type 7) is a keyframe marker, a plain P slice is not */
	char h264sps[8] = { 0x18, 0x00, 0x03, 0x67, 0x42, (char)0xe0, 0x1f, 0x00 };
	char h264p[8] = { 0x41, (char)0x9a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
	CHECK("h264.keyframe_sps", janus_h264_is_keyframe(h264sps, sizeof(h264sps)));
	CHECK("h264.not_keyframe", !janus_h264_is_keyframe(h264p, sizeof(h264p)));
}

static void test_rtcp(void) {
	char buf[64];
	int len;

	/* PLI: V=2 FMT=1 PT=206 len=2, sender 0x11111111, media 0x22222222 */
	memset(buf, 0, sizeof(buf));
	len = janus_rtcp_pli(buf, 12);
	CHECK("rtcp.pli_len", len == 12);
	CHECK("rtcp.pli_header", (uint8_t)buf[0] == 0x81 && (uint8_t)buf[1] == 206 && buf[2] == 0 && buf[3] == 2);
	CHECK("rtcp.is_rtcp", janus_is_rtcp(buf, len));
	CHECK("rtcp.has_pli", janus_rtcp_has_pli(buf, len));
	CHECK("rtcp.pli_not_fir", !janus_rtcp_has_fir(buf, len));
	CHECK("rtcp.pli_not_bye", !janus_rtcp_has_bye(buf, len));

	int seqnr = 5;
	memset(buf, 0, sizeof(buf));
	len = janus_rtcp_fir(buf, 20, &seqnr);
	CHECK("rtcp.fir_len", len == 20);
	CHECK("rtcp.has_fir", janus_rtcp_has_fir(buf, len));
	CHECK("rtcp.fir_seqnr_advanced", seqnr == 6 && (uint8_t)buf[16] == 6);
	CHECK("rtcp.fir_not_pli", !janus_rtcp_has_pli(buf, len));

	/* BYE for ssrc 0x01020304 */
	char bye[8] = { (char)0x81, (char)203, 0x00, 0x01, 0x01, 0x02, 0x03, 0x04 };
	CHECK("rtcp.has_bye", janus_rtcp_has_bye(bye, sizeof(bye)));
	CHECK("rtcp.bye_not_pli", !janus_rtcp_has_pli(bye, sizeof(bye)));

	/* REMB: 256000 bps survives the exponent/mantissa encoding exactly; 1000000 is truncated to 999424 */
	memset(buf, 0, sizeof(buf));
	len = janus_rtcp_remb(buf, 24, 256000);
	CHECK("rtcp.remb_len", len == 0 || len == 24);
	CHECK("rtcp.remb_value", janus_rtcp_get_remb(buf, 24) == 256000);
	CHECK("rtcp.remb_cap", janus_rtcp_cap_remb(buf, 24, 128000) >= 0 && janus_rtcp_get_remb(buf, 24) == 128000);
	CHECK("rtcp.remb_cap_zero_noop", janus_rtcp_cap_remb(buf, 24, 0) == 0 && janus_rtcp_get_remb(buf, 24) == 128000);
	CHECK("rtcp.remb_too_short", janus_rtcp_remb(buf, 8, 256000) < 0);

	/* Sender report: ssrc 0xAABBCCDD, no blocks */
	char sr[28] = { (char)0x80, (char)200, 0x00, 0x06, (char)0xAA, (char)0xBB, (char)0xCC, (char)0xDD };
	CHECK("rtcp.sr_is_rtcp", janus_is_rtcp(sr, sizeof(sr)));
	CHECK("rtcp.sr_sender_ssrc", janus_rtcp_get_sender_ssrc(sr, sizeof(sr)) == 0xAABBCCDD);
	CHECK("rtcp.truncated_not_rtcp", !janus_is_rtcp(sr, 6));

	/* Receiver report with one block: sender 0x01010101, media ssrc 0x02020202 */
	char rr[32] = { (char)0x81, (char)201, 0x00, 0x07, 0x01, 0x01, 0x01, 0x01, 0x02, 0x02, 0x02, 0x02 };
	CHECK("rtcp.rr_sender_ssrc", janus_rtcp_get_sender_ssrc(rr, sizeof(rr)) == 0x01010101);
	CHECK("rtcp.rr_receiver_ssrc", janus_rtcp_get_receiver_ssrc(rr, sizeof(rr)) == 0x02020202);
	char *filtered = NULL;
	int newlen = 0;
	/* Janus generates SR/RR itself, so a lone RR is filtered away entirely */
	filtered = janus_rtcp_filter(rr, sizeof(rr), &newlen);
	CHECK("rtcp.filter_drops_rr", filtered == NULL && newlen == 0);
	g_free(filtered);
	/* ...while a PLI is relayed untouched */
	memset(buf, 0, sizeof(buf));
	len = janus_rtcp_pli(buf, 12);
	filtered = janus_rtcp_filter(buf, len, &newlen);
	CHECK("rtcp.filter_keeps_pli", filtered != NULL && newlen == 12 && !memcmp(filtered, buf, 12));
	g_free(filtered);

	/* NACK feedback: generic NACK for pid 100 with BLP bit 0 (also 101) */
	GSList *nacks = NULL;
	nacks = g_slist_append(nacks, GUINT_TO_POINTER(100));
	nacks = g_slist_append(nacks, GUINT_TO_POINTER(101));
	memset(buf, 0, sizeof(buf));
	len = janus_rtcp_nacks(buf, sizeof(buf), nacks);
	g_slist_free(nacks);
	GQueue *queue = g_queue_new();
	janus_rtcp_get_nacks(buf, len > 0 ? len : 0, queue);
	CHECK("rtcp.nack_len", len == 16);
	/* Entries are pushed at the head, so the last NACKed sequence number comes out first */
	CHECK("rtcp.nack_roundtrip", len > 0 && g_queue_get_length(queue) == 2 &&
		GPOINTER_TO_UINT(g_queue_peek_head(queue)) == 101 && GPOINTER_TO_UINT(g_queue_peek_tail(queue)) == 100);
	g_queue_free(queue);
}

int main(void) {
	test_sdp();
	test_rtp();
	test_rtcp();
	printf("SUMMARY total=%d failed=%d\n", total, failed);
	return failed ? 1 : 0;
}
