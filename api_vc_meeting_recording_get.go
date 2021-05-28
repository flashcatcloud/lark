// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetVCMeetingRecording 获取一个会议的录制文件。
//
// 会议结束后并且收到了"录制完成"的事件方可获取录制文件；只有会议owner（通过开放平台预约的会议即为预约人）有权限获取；录制时间太短(&lt;5s)有可能无法生成录制文件
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/vc-v1/meeting-recording/get
func (r *VCService) GetVCMeetingRecording(ctx context.Context, request *GetVCMeetingRecordingReq, options ...MethodOptionFunc) (*GetVCMeetingRecordingResp, *Response, error) {
	if r.cli.mock.mockVCGetVCMeetingRecording != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] VC#GetVCMeetingRecording mock enable")
		return r.cli.mock.mockVCGetVCMeetingRecording(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:               "VC",
		API:                 "GetVCMeetingRecording",
		Method:              "GET",
		URL:                 "https://open.feishu.cn/open-apis/vc/v1/meetings/:meeting_id/recording",
		Body:                request,
		MethodOption:        newMethodOption(options),
		NeedUserAccessToken: true,
	}
	resp := new(getVCMeetingRecordingResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockVCGetVCMeetingRecording(f func(ctx context.Context, request *GetVCMeetingRecordingReq, options ...MethodOptionFunc) (*GetVCMeetingRecordingResp, *Response, error)) {
	r.mockVCGetVCMeetingRecording = f
}

func (r *Mock) UnMockVCGetVCMeetingRecording() {
	r.mockVCGetVCMeetingRecording = nil
}

type GetVCMeetingRecordingReq struct {
	MeetingID string `path:"meeting_id" json:"-"` // 会议ID, 示例值："6911188411932033028"
}

type getVCMeetingRecordingResp struct {
	Code int64                      `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                     `json:"msg,omitempty"`  // 错误描述
	Data *GetVCMeetingRecordingResp `json:"data,omitempty"`
}

type GetVCMeetingRecordingResp struct {
	Recording *GetVCMeetingRecordingRespRecording `json:"recording,omitempty"` // 录制文件数据
}

type GetVCMeetingRecordingRespRecording struct {
	URL      string `json:"url,omitempty"`      // 录指文件URL
	Duration string `json:"duration,omitempty"` // 录制总时长（单位msec）
}
