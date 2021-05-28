// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetCalendarList
//
// 该接口用于分页获得当前身份（应用 / 用户）的日历列表。
// 身份由 Header Authorization 的 Token 类型决定。
// 调用时首先使用 page_token 分页拉取存量数据，之后使用 sync_token 增量同步变更数据。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/calendar-v4/calendar/list
func (r *CalendarService) GetCalendarList(ctx context.Context, request *GetCalendarListReq, options ...MethodOptionFunc) (*GetCalendarListResp, *Response, error) {
	if r.cli.mock.mockCalendarGetCalendarList != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Calendar#GetCalendarList mock enable")
		return r.cli.mock.mockCalendarGetCalendarList(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Calendar",
		API:                   "GetCalendarList",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/calendar/v4/calendars",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getCalendarListResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockCalendarGetCalendarList(f func(ctx context.Context, request *GetCalendarListReq, options ...MethodOptionFunc) (*GetCalendarListResp, *Response, error)) {
	r.mockCalendarGetCalendarList = f
}

func (r *Mock) UnMockCalendarGetCalendarList() {
	r.mockCalendarGetCalendarList = nil
}

type GetCalendarListReq struct {
	PageSize  *int64  `query:"page_size" json:"-"`  // 一次请求要求返回最大数量，默认500，取值范围为[50. 1000], 示例值：10, 默认值: `500`, 取值范围：`50` ～ `1000`
	PageToken *string `query:"page_token" json:"-"` // 上次请求Response返回的分页标记，首次请求时为空, 示例值："xxxxx"
	SyncToken *string `query:"sync_token" json:"-"` // 上次请求Response返回的增量同步标记，分页请求未结束时为空, 示例值："ListCalendarsSyncToken_xxx"
}

type getCalendarListResp struct {
	Code int64                `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string               `json:"msg,omitempty"`  // 错误描述
	Data *GetCalendarListResp `json:"data,omitempty"`
}

type GetCalendarListResp struct {
	HasMore      bool                           `json:"has_more,omitempty"`      // 是否有下一页数据
	PageToken    string                         `json:"page_token,omitempty"`    // 下次请求需要带上的分页标记，90 天有效期
	SyncToken    string                         `json:"sync_token,omitempty"`    // 下次请求需要带上的增量同步标记，90 天有效期
	CalendarList []*GetCalendarListRespCalendar `json:"calendar_list,omitempty"` // 分页加载的日历数据列表
}

type GetCalendarListRespCalendar struct {
	CalendarID   string             `json:"calendar_id,omitempty"`    // 日历ID
	Summary      string             `json:"summary,omitempty"`        // 日历标题, 最大长度：`255` 字符
	Description  string             `json:"description,omitempty"`    // 日历描述, 最大长度：`255` 字符
	Permissions  CalendarPermission `json:"permissions,omitempty"`    // 日历公开范围, 可选值有: `private`：私密, `show_only_free_busy`：仅展示忙闲信息, `public`：他人可查看日程详情
	Color        int64              `json:"color,omitempty"`          // 日历颜色，颜色RGB值的int32表示。客户端展示时会映射到色板上最接近的一种颜色。仅对当前身份生效
	Type         CalendarType       `json:"type,omitempty"`           // 日历类型, 可选值有: `unknown`：未知类型, `primary`：用户或应用的主日历, `shared`：由用户或应用创建的共享日历, `google`：用户绑定的谷歌日历, `resource`：会议室日历, `exchange`：用户绑定的Exchange日历
	SummaryAlias string             `json:"summary_alias,omitempty"`  // 日历备注名，修改或添加后仅对当前身份生效, 最大长度：`255` 字符
	IsDeleted    bool               `json:"is_deleted,omitempty"`     // 对于当前身份，日历是否已经被标记为删除, 默认值: `false`
	IsThirdParty bool               `json:"is_third_party,omitempty"` // 当前日历是否是第三方数据；三方日历及日程只支持读，不支持写入, 默认值: `false`
	Role         CalendarRole       `json:"role,omitempty"`           // 当前身份对于该日历的访问权限, 可选值有: `unknown`：未知权限, `free_busy_reader`：游客，只能看到忙碌/空闲信息, `reader`：订阅者，查看所有日程详情, `writer`：编辑者，创建及修改日程, `owner`：管理员，管理日历及共享设置
}
