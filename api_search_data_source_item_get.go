// Code generated by lark_sdk_gen. DO NOT EDIT.

package lark

import (
	"context"
)

// GetSearchDataSourceItem 获取单个数据记录
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/search-v2/data_source-item/get
func (r *SearchService) GetSearchDataSourceItem(ctx context.Context, request *GetSearchDataSourceItemReq, options ...MethodOptionFunc) (*GetSearchDataSourceItemResp, *Response, error) {
	if r.cli.mock.mockSearchGetSearchDataSourceItem != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Search#GetSearchDataSourceItem mock enable")
		return r.cli.mock.mockSearchGetSearchDataSourceItem(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Search",
		API:                   "GetSearchDataSourceItem",
		Method:                "GET",
		URL:                   "https://open.feishu.cn/open-apis/search/v2/data_sources/:data_source_id/items/:item_id",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getSearchDataSourceItemResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

func (r *Mock) MockSearchGetSearchDataSourceItem(f func(ctx context.Context, request *GetSearchDataSourceItemReq, options ...MethodOptionFunc) (*GetSearchDataSourceItemResp, *Response, error)) {
	r.mockSearchGetSearchDataSourceItem = f
}

func (r *Mock) UnMockSearchGetSearchDataSourceItem() {
	r.mockSearchGetSearchDataSourceItem = nil
}

type GetSearchDataSourceItemReq struct {
	DataSourceID string `path:"data_source_id" json:"-"` // 数据源的id, 示例值："service_ticket"
	ItemID       string `path:"item_id" json:"-"`        // 数据记录的唯一标识, 示例值："01010111"
}

type getSearchDataSourceItemResp struct {
	Code int64                        `json:"code,omitempty"` // 错误码，非 0 表示失败
	Msg  string                       `json:"msg,omitempty"`  // 错误描述
	Data *GetSearchDataSourceItemResp `json:"data,omitempty"`
}

type GetSearchDataSourceItemResp struct {
	Item *GetSearchDataSourceItemRespItem `json:"item,omitempty"` // 数据项实例
}

type GetSearchDataSourceItemRespItem struct {
	ID             string                                   `json:"id,omitempty"`              // item 在 datasource 中的唯一标识
	ACL            *GetSearchDataSourceItemRespItemACL      `json:"acl,omitempty"`             // item 的访问权限控制
	Metadata       *GetSearchDataSourceItemRespItemMetadata `json:"metadata,omitempty"`        // item 的元信息
	StructuredData string                                   `json:"structured_data,omitempty"` // 结构化数据（以 json 字符串传递）
	Content        *GetSearchDataSourceItemRespItemContent  `json:"content,omitempty"`         // 非结构化数据，如文档文本
}

type GetSearchDataSourceItemRespItemACL struct {
	Access string `json:"access,omitempty"` // 权限类型，优先级：Deny > Allow, 可选值有: `1`：允许访问, `2`：禁止访问
	Value  string `json:"value,omitempty"`  // 设置的权限值，例如 userID 、groupID，依赖 type 描述
	Type   string `json:"type,omitempty"`   // 权限值类型, 可选值有: `1`：访问权限控制中指定用户可以访问或拒绝访问该条数据, `2`：访问权限控制中指定用户组可以访问或拒绝访问该条数据
}

type GetSearchDataSourceItemRespItemMetadata struct {
	Title      string `json:"title,omitempty"`       // 该条数据记录对应的标题
	SourceURL  string `json:"source_url,omitempty"`  // 该条数据记录对应的跳转url
	CreateTime int64  `json:"create_time,omitempty"` // 数据项的创建时间
	UpdateTime int64  `json:"update_time,omitempty"` // 数据项的更新时间
}

type GetSearchDataSourceItemRespItemContent struct {
	Format      string `json:"format,omitempty"`       // 内容的格式, 可选值有: `0`：html格式, `1`：纯文本格式
	ContentData string `json:"content_data,omitempty"` // 全文数据
}
