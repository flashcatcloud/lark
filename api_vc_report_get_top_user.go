// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetVCTopUserReport 获取一段时间内组织内会议使用的top用户列表。
//
// 支持最近90天内的数据查询；默认返回前10位，最多可查询前100位
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/vc-v1/report/get_top_user
func (r *VCService) GetVCTopUserReport(ctx context.Context, request *GetVCTopUserReportReq, options ...MethodOptionFunc) (*GetVCTopUserReportResp, *Response, error) {
	if r.cli.mock.mockVCGetVCTopUserReport != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] VC#GetVCTopUserReport mock enable")
		return r.cli.mock.mockVCGetVCTopUserReport(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "VC",
		API:                   "GetVCTopUserReport",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/vc/v1/reports/get_top_user",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getVCTopUserReportResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockVCGetVCTopUserReport(f func(ctx context.Context, request *GetVCTopUserReportReq, options ...MethodOptionFunc) (*GetVCTopUserReportResp, *Response, error)) {
	r.mockVCGetVCTopUserReport = f
}

func (r *Mock) UnMockVCGetVCTopUserReport() {
	r.mockVCGetVCTopUserReport = nil
}

type GetVCTopUserReportReq struct {
	StartTime string `query:"start_time" json:"-"` // 开始时间（unix时间，单位sec）, 示例值："1608888867"
	EndTime   string `query:"end_time" json:"-"`   // 结束时间（unix时间，单位sec）, 示例值："1608889966"
	Limit     int64  `query:"limit" json:"-"`      // 取前多少位, 示例值：10
	OrderBy   int64  `query:"order_by" json:"-"`   // 排序依据（降序）, 示例值：1, 可选值有: `1`：会议数量, `2`：会议时长
}

type getVCTopUserReportResp struct {
	Code int64                   `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                  `json:"msg,omitempty"`  // 错误描述
	Data *GetVCTopUserReportResp `json:"data,omitempty"`
}

type GetVCTopUserReportResp struct {
	TopUserReport *GetVCTopUserReportRespTopUserReport `json:"top_user_report,omitempty"` // top用户列表
}

type GetVCTopUserReportRespTopUserReport struct {
	ID              string `json:"id,omitempty"`               // 用户ID
	Name            string `json:"name,omitempty"`             // 用户名
	UserType        int64  `json:"user_type,omitempty"`        // 用户类型, 可选值有: `1`：lark用户, `2`：rooms用户, `3`：文档用户, `4`：neo单品用户, `5`：neo单品游客用户, `6`：pstn用户, `7`：sip用户
	MeetingCount    string `json:"meeting_count,omitempty"`    // 会议数量
	MeetingDuration string `json:"meeting_duration,omitempty"` // 会议时长（单位sec）
}
