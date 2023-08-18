// Code generated by lark_sdk_gen. DO NOT EDIT.
/**
 * Copyright 2022 chyroc
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package lark

import (
	"context"
)

// GetCalendarEvent 该接口用于以当前身份（应用 / 用户）获取日历上的一个日程。
//
// 身份由 Header Authorization 的 Token 类型决定。
// - 当前身份必须对日历有reader、writer或owner权限才会返回日程详细信息（调用[获取日历](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar/get)接口, role字段可查看权限）。
// - [例外日程](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar-event/introduction#71c5ec78)可通过event_id的非0时间戳后缀, 来获取修改的重复性日程的哪一天日程的时间信息。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar-event/get
// new doc: https://open.feishu.cn/document/server-docs/calendar-v4/calendar-event/get
func (r *CalendarService) GetCalendarEvent(ctx context.Context, request *GetCalendarEventReq, options ...MethodOptionFunc) (*GetCalendarEventResp, *Response, error) {
	if r.cli.mock.mockCalendarGetCalendarEvent != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Calendar#GetCalendarEvent mock enable")
		return r.cli.mock.mockCalendarGetCalendarEvent(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Calendar",
		API:                   "GetCalendarEvent",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/calendar/v4/calendars/:calendar_id/events/:event_id",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getCalendarEventResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockCalendarGetCalendarEvent mock CalendarGetCalendarEvent method
func (r *Mock) MockCalendarGetCalendarEvent(f func(ctx context.Context, request *GetCalendarEventReq, options ...MethodOptionFunc) (*GetCalendarEventResp, *Response, error)) {
	r.mockCalendarGetCalendarEvent = f
}

// UnMockCalendarGetCalendarEvent un-mock CalendarGetCalendarEvent method
func (r *Mock) UnMockCalendarGetCalendarEvent() {
	r.mockCalendarGetCalendarEvent = nil
}

// GetCalendarEventReq ...
type GetCalendarEventReq struct {
	CalendarID          string  `path:"calendar_id" json:"-"`            // 日历ID。参见[日历ID说明](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar/introduction), 示例值: "feishu.cn_xxxxxxxxxx@group.calendar.feishu.cn"
	EventID             string  `path:"event_id" json:"-"`               // 日程ID。参见[日程ID说明](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar-event/introduction), 示例值: "xxxxxxxxx_0"
	NeedMeetingSettings *bool   `query:"need_meeting_settings" json:"-"` // 是否需要返回会前设置, 日程的会议类型(vc_type)为vc, 需要有日程的编辑权限, 示例值: false
	UserIDType          *IDType `query:"user_id_type" json:"-"`          // 用户 ID 类型, 示例值: open_id, 可选值有: open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
}

// GetCalendarEventResp ...
type GetCalendarEventResp struct {
	Event *GetCalendarEventRespEvent `json:"event,omitempty"` // 日程实体
}

// GetCalendarEventRespEvent ...
type GetCalendarEventRespEvent struct {
	EventID             string                               `json:"event_id,omitempty"`              // 日程ID。参见[日程ID说明](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar-event/introduction)
	OrganizerCalendarID string                               `json:"organizer_calendar_id,omitempty"` // 日程组织者日历ID。参见[日历ID说明](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar/introduction)
	Summary             string                               `json:"summary,omitempty"`               // 日程标题
	Description         string                               `json:"description,omitempty"`           // 日程描述；目前不支持编辑富文本描述, 如果日程描述通过客户端编辑过, 更新描述会导致富文本格式丢失
	StartTime           *GetCalendarEventRespEventStartTime  `json:"start_time,omitempty"`            // 日程开始时间
	EndTime             *GetCalendarEventRespEventEndTime    `json:"end_time,omitempty"`              // 日程结束时间
	Vchat               *GetCalendarEventRespEventVchat      `json:"vchat,omitempty"`                 // 视频会议信息。
	Visibility          string                               `json:"visibility,omitempty"`            // 日程公开范围, 新建日程默认为Default；仅新建日程时对所有参与人生效, 之后修改该属性仅对当前身份生效, 可选值有: default: 默认权限, 跟随日历权限, 默认仅向他人显示是否“忙碌”, public: 公开, 显示日程详情, private: 私密, 仅自己可见详情
	AttendeeAbility     string                               `json:"attendee_ability,omitempty"`      // 参与人权限, 可选值有: none: 无法编辑日程、无法邀请其它参与人、无法查看参与人列表, can_see_others: 无法编辑日程、无法邀请其它参与人、可以查看参与人列表, can_invite_others: 无法编辑日程、可以邀请其它参与人、可以查看参与人列表, can_modify_event: 可以编辑日程、可以邀请其它参与人、可以查看参与人列表
	FreeBusyStatus      string                               `json:"free_busy_status,omitempty"`      // 日程占用的忙闲状态, 新建日程默认为Busy；仅新建日程时对所有参与人生效, 之后修改该属性仅对当前身份生效, 可选值有: busy: 忙碌, free: 空闲
	Location            *GetCalendarEventRespEventLocation   `json:"location,omitempty"`              // 日程地点
	Color               int64                                `json:"color,omitempty"`                 // 日程颜色, 颜色RGB值的int32表示。仅对当前身份生效；客户端展示时会映射到色板上最接近的一种颜色；值为0或-1时默认跟随日历颜色。
	Reminders           []*GetCalendarEventRespEventReminder `json:"reminders,omitempty"`             // 日程提醒列表
	Recurrence          string                               `json:"recurrence,omitempty"`            // 重复日程的重复性规则；参考[rfc5545](https://datatracker.ietf.org/doc/html/rfc5545#section-3.3.10)；, 不支持COUNT和UNTIL同时出现；, 预定会议室重复日程长度不得超过两年。
	Status              string                               `json:"status,omitempty"`                // 日程状态, 可选值有: tentative: 未回应, confirmed: 已确认, cancelled: 日程已取消
	IsException         bool                                 `json:"is_exception,omitempty"`          // 日程是否是一个重复日程的例外日程
	RecurringEventID    string                               `json:"recurring_event_id,omitempty"`    // 例外日程的原重复日程的event_id
	CreateTime          string                               `json:"create_time,omitempty"`           // 日程的创建时间（秒级时间戳）
	Schemas             []*GetCalendarEventRespEventSchema   `json:"schemas,omitempty"`               // 日程自定义信息；控制日程详情页的ui展示。
}

// GetCalendarEventRespEventEndTime ...
type GetCalendarEventRespEventEndTime struct {
	Date      string `json:"date,omitempty"`      // 仅全天日程使用该字段, 如2018-09-01。需满足 RFC3339 格式。不能与 timestamp 同时指定
	Timestamp string `json:"timestamp,omitempty"` // 秒级时间戳, 如1602504000(表示2020/10/12 20:0:00 +8时区)
	Timezone  string `json:"timezone,omitempty"`  // 时区名称, 使用IANA Time Zone Database标准, 如Asia/Shanghai；全天日程时区固定为UTC, 非全天日程时区默认为Asia/Shanghai
}

// GetCalendarEventRespEventLocation ...
type GetCalendarEventRespEventLocation struct {
	Name      string  `json:"name,omitempty"`      // 地点名称
	Address   string  `json:"address,omitempty"`   // 地点地址
	Latitude  float64 `json:"latitude,omitempty"`  // 地点坐标纬度信息, 对于国内的地点, 采用GCJ-02标准, 海外地点采用WGS84标准
	Longitude float64 `json:"longitude,omitempty"` // 地点坐标经度信息, 对于国内的地点, 采用GCJ-02标准, 海外地点采用WGS84标准
}

// GetCalendarEventRespEventReminder ...
type GetCalendarEventRespEventReminder struct {
	Minutes int64 `json:"minutes,omitempty"` // 日程提醒时间的偏移量, 正数时表示在日程开始前X分钟提醒, 负数时表示在日程开始后X分钟提醒, 新建或更新日程时传入该字段, 仅对当前身份生效, 不会对日程其他参与人生效。
}

// GetCalendarEventRespEventSchema ...
type GetCalendarEventRespEventSchema struct {
	UiName   string `json:"ui_name,omitempty"`   // UI名称。取值范围如下: ForwardIcon: 日程转发按钮, MeetingChatIcon: 会议群聊按钮, MeetingMinutesIcon: 会议纪要按钮, MeetingVideo: 视频会议区域, RSVP: 接受/拒绝/待定区域, Attendee: 参与者区域, OrganizerOrCreator: 组织者/创建者区域
	UiStatus string `json:"ui_status,omitempty"` // UI项自定义状态。目前只支持hide, 可选值有: hide: 隐藏显示, readonly: 只读, editable: 可编辑, unknown: 未知UI项自定义状态, 仅用于读取时兼容
	AppLink  string `json:"app_link,omitempty"`  // 按钮点击后跳转的链接; 该字段暂不支持传入。
}

// GetCalendarEventRespEventStartTime ...
type GetCalendarEventRespEventStartTime struct {
	Date      string `json:"date,omitempty"`      // 仅全天日程使用该字段, 如2018-09-01。需满足 RFC3339 格式。不能与 timestamp 同时指定
	Timestamp string `json:"timestamp,omitempty"` // 秒级时间戳, 如1602504000(表示2020/10/12 20:0:00 +8时区)
	Timezone  string `json:"timezone,omitempty"`  // 时区名称, 使用IANA Time Zone Database标准, 如Asia/Shanghai；全天日程时区固定为UTC, 非全天日程时区默认为Asia/Shanghai
}

// GetCalendarEventRespEventVchat ...
type GetCalendarEventRespEventVchat struct {
	VCType          string                                         `json:"vc_type,omitempty"`          // 视频会议类型；可以为空, 为空会在首次添加日程参与人时, 自动生成飞书视频会议URL。若无需视频会议时需显式传入no_meeting, 可选值有: vc: 飞书视频会议, 取该类型时, 其他字段无效。, third_party: 第三方链接视频会议, 取该类型时, icon_type、description、meeting_url字段生效。, no_meeting: 无视频会议, 取该类型时, 其他字段无效。, lark_live: 飞书直播, 内部类型, 飞书客户端使用, API不支持创建, 只读。, unknown: 未知类型, 做兼容使用, 飞书客户端使用, API不支持创建, 只读。
	IconType        string                                         `json:"icon_type,omitempty"`        // 第三方视频会议icon类型；可以为空, 为空展示默认icon, 可选值有: vc: 飞书视频会议icon, live: 直播视频会议icon, default: 默认icon
	Description     string                                         `json:"description,omitempty"`      // 第三方视频会议文案, 可以为空, 为空展示默认文案
	MeetingURL      string                                         `json:"meeting_url,omitempty"`      // 视频会议URL
	MeetingSettings *GetCalendarEventRespEventVchatMeetingSettings `json:"meeting_settings,omitempty"` // VC视频会议的会前设置。需要满足以下条件(需全部满足): 当vc_type为vc时生效, 需要有日程的编辑权限。
}

// GetCalendarEventRespEventVchatMeetingSettings ...
type GetCalendarEventRespEventVchatMeetingSettings struct {
	OwnerID               string   `json:"owner_id,omitempty"`                // 设置会议 owner。需要满足以下条件(需全部满足): tenant_access_token身份请求, 且在应用日历上操作日程, 首次将日程设置为VC会议, 才能设置owner, owner不能为非用户身份, owner不能为外租户用户身份。
	JoinMeetingPermission string   `json:"join_meeting_permission,omitempty"` // 设置入会范围, 可选值有: anyone_can_join: 所有人可以加入会议, only_organization_employees: 仅企业内用户可以加入会议, only_event_attendees: 仅日程参与者可以加入会议
	AssignHosts           []string `json:"assign_hosts,omitempty"`            // 指定主持人, 仅日程组织者可以指定主持人, 主持人不能是非用户身份, 主持人不能是外租户用户身份, 应用日历上操作日程时, 不允许指定主持人。
	AutoRecord            bool     `json:"auto_record,omitempty"`             // 设置自动录制
	OpenLobby             bool     `json:"open_lobby,omitempty"`              // 开启等候室
	AllowAttendeesStart   bool     `json:"allow_attendees_start,omitempty"`   // 允许日程参与者发起会议, 应用日历上操作日程时, 该字段必须为true, 否则没有人能发起会议。
}

// getCalendarEventResp ...
type getCalendarEventResp struct {
	Code int64                 `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                `json:"msg,omitempty"`  // 错误描述
	Data *GetCalendarEventResp `json:"data,omitempty"`
}
