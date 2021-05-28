// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetHireJobProcessList 获取全部招聘流程信息
//
// doc: https://open.feishu.cn/document/ukTMukTMukTM/uMzM1YjLzMTN24yMzUjN/hire-v1/job_process/list
func (r *HireService) GetHireJobProcessList(ctx context.Context, request *GetHireJobProcessListReq, options ...MethodOptionFunc) (*GetHireJobProcessListResp, *Response, error) {
	if r.cli.mock.mockHireGetHireJobProcessList != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Hire#GetHireJobProcessList mock enable")
		return r.cli.mock.mockHireGetHireJobProcessList(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Hire",
		API:                   "GetHireJobProcessList",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/hire/v1/job_processes",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getHireJobProcessListResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockHireGetHireJobProcessList(f func(ctx context.Context, request *GetHireJobProcessListReq, options ...MethodOptionFunc) (*GetHireJobProcessListResp, *Response, error)) {
	r.mockHireGetHireJobProcessList = f
}

func (r *Mock) UnMockHireGetHireJobProcessList() {
	r.mockHireGetHireJobProcessList = nil
}

type GetHireJobProcessListReq struct {
	PageSize  *int64  `query:"page_size" json:"-"`  // 分页大小, 不能超过 100, 示例值：10
	PageToken *string `query:"page_token" json:"-"` // 分页标记，第一次请求不填，表示从头开始遍历；分页查询结果还有更多项时会同时返回新的 page_token，下次遍历可采用该 page_token 获取查询结果, 示例值："1"
}

type getHireJobProcessListResp struct {
	Code int64                      `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                     `json:"msg,omitempty"`  // 错误描述
	Data *GetHireJobProcessListResp `json:"data,omitempty"`
}

type GetHireJobProcessListResp struct {
	HasMore   bool                             `json:"has_more,omitempty"`   // 是否还有更多项
	PageToken string                           `json:"page_token,omitempty"` // 分页标记，当 has_more 为 true 时，会同时返回新的 page_token，否则不返回 page_token
	Items     []*GetHireJobProcessListRespItem `json:"items,omitempty"`      // 列表
}

type GetHireJobProcessListRespItem struct {
	ID        string                                `json:"id,omitempty"`         // ID
	ZhName    string                                `json:"zh_name,omitempty"`    // 中文名称
	EnName    string                                `json:"en_name,omitempty"`    // 英文名称
	Type      int64                                 `json:"type,omitempty"`       // 类型 1=社招流程, 2=校招流程,, 可选值有: `1`：社招流程, `2`：校招流程
	StageList []*GetHireJobProcessListRespItemStage `json:"stage_list,omitempty"` // 阶段列表, 内部按用户设置顺序排列
}

type GetHireJobProcessListRespItemStage struct {
	ID     string `json:"id,omitempty"`      // ID
	ZhName string `json:"zh_name,omitempty"` // 中文名称
	EnName string `json:"en_name,omitempty"` // 英文名称
	Type   int64  `json:"type,omitempty"`    // 1=筛选型, 2=评估型, 3=笔试型, 4=面试型, 5=Offer型, 6=待入职, 7=已入职, 8=其它类型, 255=系统默认，后端模型中并没有该字段，仅用于前端显示,, 可选值有: `1`：筛选型, `2`：评估型, `3`：笔试型, `4`：面试型, `5`：Offer型, `6`：待入职, `7`：已入职, `8`：其它类型, `255`：系统默认
}
