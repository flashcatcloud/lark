// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetVCReserveActiveMeeting 获取一个预约的当前活跃会议
//
// 只能获取归属于自己的预约的活跃会议（一个预约最多有一个正在进行中的会议）
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/vc-v1/reserve/get_active_meeting
func (r *VCService) GetVCReserveActiveMeeting(ctx context.Context, request *GetVCReserveActiveMeetingReq, options ...MethodOptionFunc) (*GetVCReserveActiveMeetingResp, *Response, error) {
	if r.cli.mock.mockVCGetVCReserveActiveMeeting != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] VC#GetVCReserveActiveMeeting mock enable")
		return r.cli.mock.mockVCGetVCReserveActiveMeeting(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:               "VC",
		API:                 "GetVCReserveActiveMeeting",
		Method:              "GET",
		URL:                 "https://open.feishu.cn/open-apis/vc/v1/reserves/:reserve_id/get_active_meeting",
		Body:                request,
		MethodOption:        newMethodOption(options),
		NeedUserAccessToken: true,
	}
	resp := new(getVCReserveActiveMeetingResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockVCGetVCReserveActiveMeeting(f func(ctx context.Context, request *GetVCReserveActiveMeetingReq, options ...MethodOptionFunc) (*GetVCReserveActiveMeetingResp, *Response, error)) {
	r.mockVCGetVCReserveActiveMeeting = f
}

func (r *Mock) UnMockVCGetVCReserveActiveMeeting() {
	r.mockVCGetVCReserveActiveMeeting = nil
}

type GetVCReserveActiveMeetingReq struct {
	WithParticipants *bool  `query:"with_participants" json:"-"` // 是否需要参会人列表，默认为false, 示例值：false
	ReserveID        string `path:"reserve_id" json:"-"`         // 预约ID, 示例值："6911188411932033028"
}

type getVCReserveActiveMeetingResp struct {
	Code int64                          `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                         `json:"msg,omitempty"`  // 错误描述
	Data *GetVCReserveActiveMeetingResp `json:"data,omitempty"`
}

type GetVCReserveActiveMeetingResp struct {
	Meeting *GetVCReserveActiveMeetingRespMeeting `json:"meeting,omitempty"` // 会议数据
}

type GetVCReserveActiveMeetingRespMeeting struct {
	ID               string                                             `json:"id,omitempty"`                // 会议ID
	Topic            string                                             `json:"topic,omitempty"`             // 会议主题
	URL              string                                             `json:"url,omitempty"`               // 会议链接
	CreateTime       string                                             `json:"create_time,omitempty"`       // 会议创建时间（unix时间，单位sec）
	StartTime        string                                             `json:"start_time,omitempty"`        // 会议开始时间（unix时间，单位sec）
	EndTime          string                                             `json:"end_time,omitempty"`          // 会议结束时间（unix时间，单位sec）
	HostUser         *GetVCReserveActiveMeetingRespMeetingHostUser      `json:"host_user,omitempty"`         // 主持人
	Status           int64                                              `json:"status,omitempty"`            // 会议状态, 可选值有: `1`：会议呼叫中, `2`：会议进行中, `3`：会议已结束
	ParticipantCount string                                             `json:"participant_count,omitempty"` // 参会人数
	Participants     []*GetVCReserveActiveMeetingRespMeetingParticipant `json:"participants,omitempty"`      // 参会人列表
	Ability          *GetVCReserveActiveMeetingRespMeetingAbility       `json:"ability,omitempty"`           // 会中使用的能力
}

type GetVCReserveActiveMeetingRespMeetingHostUser struct {
	ID       string `json:"id,omitempty"`        // 用户ID
	UserType int64  `json:"user_type,omitempty"` // 用户类型, 可选值有: `1`：lark用户, `2`：rooms用户, `3`：文档用户, `4`：neo单品用户, `5`：neo单品游客用户, `6`：pstn用户, `7`：sip用户
}

type GetVCReserveActiveMeetingRespMeetingParticipant struct {
	ID         string `json:"id,omitempty"`          // 用户ID
	UserType   int64  `json:"user_type,omitempty"`   // 用户类型, 可选值有: `1`：lark用户, `2`：rooms用户, `3`：文档用户, `4`：neo单品用户, `5`：neo单品游客用户, `6`：pstn用户, `7`：sip用户
	IsHost     bool   `json:"is_host,omitempty"`     // 是否为主持人
	IsCohost   bool   `json:"is_cohost,omitempty"`   // 是否为联席主持人
	IsExternal bool   `json:"is_external,omitempty"` // 是否为外部参会人
	Status     int64  `json:"status,omitempty"`      // 参会人状态, 可选值有: `1`：呼叫中, `2`：在会中, `3`：正在响铃, `4`：不在会中或已经离开会议
}

type GetVCReserveActiveMeetingRespMeetingAbility struct {
	UseVideo        bool `json:"use_video,omitempty"`         // 是否使用视频
	UseAudio        bool `json:"use_audio,omitempty"`         // 是否使用音频
	UseShareScreen  bool `json:"use_share_screen,omitempty"`  // 是否使用共享屏幕
	UseFollowScreen bool `json:"use_follow_screen,omitempty"` // 是否使用妙享（magic share）
	UseRecording    bool `json:"use_recording,omitempty"`     // 是否使用录制
	UsePstn         bool `json:"use_pstn,omitempty"`          // 是否使用PSTN
}
