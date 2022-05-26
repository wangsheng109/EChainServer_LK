#ifndef CMD_DEFINITION_H
#define CMD_DEFINITION_H


//---------------------------------------------------------------------//
// command structure
typedef struct
{
	char * pName; // type name
// video
	int bVideo; // flag of video-using
	int nVideoCoder; // video coder, 0->tivc, 1->h.264, 2->h.263
// video dimension
	union
	{
		struct // for normal using
		{
			short nWot; // output width
			short nHot; // output height
		};
		int nVideoSize; // video dimension, for scripter-reading
	};
	int nVideoBitrate; // video bitrate, 0->30, 1->40, 2->50kbps
	int nVideoCodingMode; // video coding mode, 0->vbr+afr, 1->cbr+afr, 2->cbr+cfr
	int nVideoFrameRate; // video framerate, cbr+cfr only, 0->auto, 1,2,...
	int nAspectRatio; // flag of aspect ratio.
	int nIFrameInterval; // flag of I frame interval.
// audio
	int bAudio; // flag of audio-using
	int nAudioCoder; // audio coder, 0->tiac-h(amr-wb), 1->tiac-l(amr-nb), 2->aac+2channels, 3->aac+-1channel
	int nAudioBitrate; // audio bitrate, 0->7.2, 1->9.6, 2->13.2kbps
}
TCFGPRM, * PTCFGPRM;

#define NME_SZE 20


#endif

