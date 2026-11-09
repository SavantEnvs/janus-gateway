/*
 * Fuzz harness for the Record&Play plugin: index a recording (.mjr) with janus_recordplay_get_frames(),
 * then run the plugin's own playout thread over the frames it returned, against a gateway whose relay
 * callbacks discard what they are given.
 *
 * The plugin source is included so that its static playout thread can be started as the plugin starts it.
 * Input: one selector byte (which stream(s) the recording is played as), then the .mjr file.
 *
 * The playout thread paces frames by their timestamps, so a recording with a large timestamp gap would
 * keep it asleep for hours. The pacing fields of the index (never the frame lengths or offsets) are zeroed
 * so each frame is sent as soon as it is reached.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>

#include "../src/plugins/janus_recordplay.c"

static void stub_relay_rtp(janus_plugin_session *handle, janus_plugin_rtp *packet) {}
static void stub_relay_data(janus_plugin_session *handle, janus_plugin_data *packet) {}
static void stub_close_pc(janus_plugin_session *handle) {}

/* Globals the core defines, and the libraries the plugin links in the core */
int janus_log_level = LOG_NONE;
gboolean janus_log_timestamps = FALSE;
gboolean janus_log_colors = FALSE;
char *janus_log_global_prefix = NULL;
int lock_debug = 0;
int refcount_debug = 0;

int RAND_bytes(uint8_t *key, int len) {
	return 0;
}

static janus_callbacks stub_gateway = {
	.relay_rtp = stub_relay_rtp,
	.relay_data = stub_relay_data,
	.close_pc = stub_close_pc,
};

static char dir[64];
static const char *name = "rec.mjr";

int LLVMFuzzerInitialize(int *argc, char ***argv) {
	const char *tmp = getenv("TMPDIR");
	g_snprintf(dir, sizeof(dir), "%s/recordplay-fuzz-XXXXXX", tmp && *tmp ? tmp : "/tmp");
	if(mkdtemp(dir) == NULL)
		return -1;
	recordings_path = g_strdup(dir);
	gateway = &stub_gateway;
	return 0;
}

static void free_frames(janus_recordplay_frame_packet *list) {
	while(list) {
		janus_recordplay_frame_packet *next = list->next;
		g_free(list);
		list = next;
	}
}

static void zero_pacing(janus_recordplay_frame_packet *list) {
	for(; list; list = list->next)
		list->ts = 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
	if(size < 1)
		return -1;
	uint8_t mode = data[0] & 3;
	data++;
	size--;

	char path[128];
	g_snprintf(path, sizeof(path), "%s/%s", dir, name);
	FILE *f = fopen(path, "wb");
	if(f == NULL)
		return -1;
	if(size > 0 && fwrite(data, 1, size, f) != size) {
		fclose(f);
		return -1;
	}
	fclose(f);

	janus_recordplay_frame_packet *frames = janus_recordplay_get_frames(dir, name);
	if(frames == NULL) {
		remove(path);
		return 0;
	}
	zero_pacing(frames);

	janus_plugin_session handle = { 0 };
	janus_recordplay_recording *rec = g_malloc0(sizeof(janus_recordplay_recording));
	rec->audio_pt = AUDIO_PT;
	rec->video_pt = VIDEO_PT;
	rec->arc_file = g_strdup(name);
	rec->vrc_file = g_strdup(name);
	rec->drc_file = g_strdup(name);
	janus_refcount_init(&rec->ref, janus_recordplay_recording_free);
	janus_mutex_init(&rec->mutex);

	janus_recordplay_session *session = g_malloc0(sizeof(janus_recordplay_session));
	session->handle = &handle;
	session->active = TRUE;
	session->recording = rec;
	janus_refcount_init(&session->ref, janus_recordplay_session_free);
	janus_refcount_increase(&session->ref);
	rec->viewers = g_list_append(rec->viewers, session);

	if(mode & 1)
		session->vframes = frames;
	else
		session->aframes = frames;
	if(mode & 2) {
		session->dframes = janus_recordplay_get_frames(dir, name);
		zero_pacing(session->dframes);
	}

	/* The playout thread drops the GThread reference of g_thread_self() itself, which a thread made by
	 * g_thread_new() (joinable, one reference short for that) can't take: use a plain pthread */
	pthread_t thread;
	if(pthread_create(&thread, NULL, janus_recordplay_playout_thread, session) == 0)
		pthread_join(thread, NULL);

	remove(path);
	/* The thread frees the indexes only when it plays them */
	free_frames(session->aframes);
	free_frames(session->vframes);
	free_frames(session->dframes);
	g_list_free(rec->viewers);
	janus_recordplay_recording_free(&rec->ref);
	g_free(session);
	return 0;
}
