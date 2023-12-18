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

// GetDriveFileViewRecordList 获取文档的历史访问记录
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/drive-v1/file-view_record/list
// new doc: https://open.feishu.cn/document/server-docs/docs/drive-v1/file-view_record/list
func (r *DriveService) GetDriveFileViewRecordList(ctx context.Context, request *GetDriveFileViewRecordListReq, options ...MethodOptionFunc) (*GetDriveFileViewRecordListResp, *Response, error) {
	if r.cli.mock.mockDriveGetDriveFileViewRecordList != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Drive#GetDriveFileViewRecordList mock enable")
		return r.cli.mock.mockDriveGetDriveFileViewRecordList(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Drive",
		API:                   "GetDriveFileViewRecordList",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/drive/v1/files/:file_token/view_records",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getDriveFileViewRecordListResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockDriveGetDriveFileViewRecordList mock DriveGetDriveFileViewRecordList method
func (r *Mock) MockDriveGetDriveFileViewRecordList(f func(ctx context.Context, request *GetDriveFileViewRecordListReq, options ...MethodOptionFunc) (*GetDriveFileViewRecordListResp, *Response, error)) {
	r.mockDriveGetDriveFileViewRecordList = f
}

// UnMockDriveGetDriveFileViewRecordList un-mock DriveGetDriveFileViewRecordList method
func (r *Mock) UnMockDriveGetDriveFileViewRecordList() {
	r.mockDriveGetDriveFileViewRecordList = nil
}

// GetDriveFileViewRecordListReq ...
type GetDriveFileViewRecordListReq struct {
	FileToken    string   `path:"file_token" json:"-"`      // 文档 token, 示例值: "XIHSdYSI7oMEU1xrsnxc8fabcef"
	PageSize     int64    `query:"page_size" json:"-"`      // 分页大小, 示例值: 10, 取值范围: `1` ～ `50`
	PageToken    *string  `query:"page_token" json:"-"`     // 分页标记, 第一次请求不填, 表示从头开始遍历；分页查询结果还有更多项时会同时返回新的 page_token, 下次遍历可采用该 page_token 获取查询结果, 示例值: 1674037112--7189934631754563585
	FileType     FileType `query:"file_type" json:"-"`      // 文档类型, 示例值: docx, 可选值有: doc: 旧版文档, docx: 新版文档, sheet: 电子表格, bitable: 多维表格, mindnote: 思维笔记, wiki: 知识库文档, file: 文件
	ViewerIDType *IDType  `query:"viewer_id_type" json:"-"` // 此次调用中使用的访问者 ID 的类型, 当值为`user_id`时, 字段权限要求: 获取用户 user ID, 示例值: open_id, 可选值有: user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), 默认值: `open_id`
}

// GetDriveFileViewRecordListResp ...
type GetDriveFileViewRecordListResp struct {
	Items     []*GetDriveFileViewRecordListRespItem `json:"items,omitempty"`      // 访问记录列表
	PageToken string                                `json:"page_token,omitempty"` // 分页标记, 当 has_more 为 true 时, 会同时返回新的 page_token, 否则不返回 page_token
	HasMore   bool                                  `json:"has_more,omitempty"`   // 是否还有更多项
}

// GetDriveFileViewRecordListRespItem ...
type GetDriveFileViewRecordListRespItem struct {
	ViewerID     string `json:"viewer_id,omitempty"`      // 访问者 ID
	Name         string `json:"name,omitempty"`           // 访问者名称
	AvatarURL    string `json:"avatar_url,omitempty"`     // 访问者头像 URL
	LastViewTime string `json:"last_view_time,omitempty"` // 最近访问时间, 秒级时间戳
}

// getDriveFileViewRecordListResp ...
type getDriveFileViewRecordListResp struct {
	Code int64                           `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                          `json:"msg,omitempty"`  // 错误描述
	Data *GetDriveFileViewRecordListResp `json:"data,omitempty"`
}
