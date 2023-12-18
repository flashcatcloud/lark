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

// GetDriveFileStatistics 此接口用于获取文档统计信息, 包括文档阅读人数、次数和点赞数。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/drive-v1/file-statistics/get
// new doc: https://open.feishu.cn/document/server-docs/docs/drive-v1/file/get
func (r *DriveService) GetDriveFileStatistics(ctx context.Context, request *GetDriveFileStatisticsReq, options ...MethodOptionFunc) (*GetDriveFileStatisticsResp, *Response, error) {
	if r.cli.mock.mockDriveGetDriveFileStatistics != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Drive#GetDriveFileStatistics mock enable")
		return r.cli.mock.mockDriveGetDriveFileStatistics(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Drive",
		API:                   "GetDriveFileStatistics",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/drive/v1/files/:file_token/statistics",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(getDriveFileStatisticsResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockDriveGetDriveFileStatistics mock DriveGetDriveFileStatistics method
func (r *Mock) MockDriveGetDriveFileStatistics(f func(ctx context.Context, request *GetDriveFileStatisticsReq, options ...MethodOptionFunc) (*GetDriveFileStatisticsResp, *Response, error)) {
	r.mockDriveGetDriveFileStatistics = f
}

// UnMockDriveGetDriveFileStatistics un-mock DriveGetDriveFileStatistics method
func (r *Mock) UnMockDriveGetDriveFileStatistics() {
	r.mockDriveGetDriveFileStatistics = nil
}

// GetDriveFileStatisticsReq ...
type GetDriveFileStatisticsReq struct {
	FileToken string   `path:"file_token" json:"-"` // 文档 token, 示例值: "doccnfYZzTlvXqZIGTdAHKabcef"
	FileType  FileType `query:"file_type" json:"-"` // 文档类型, 示例值: doc, 可选值有: doc: 旧版文档, sheet: 电子表格, mindnote: 思维笔记, bitable: 多维表格, wiki: 知识库文档, file: 文件, docx: 新版文档
}

// GetDriveFileStatisticsResp ...
type GetDriveFileStatisticsResp struct {
	FileToken  string                                `json:"file_token,omitempty"` // 文档 token
	FileType   FileType                              `json:"file_type,omitempty"`  // 文档类型
	Statistics *GetDriveFileStatisticsRespStatistics `json:"statistics,omitempty"` // 文档统计信息
}

// GetDriveFileStatisticsRespStatistics ...
type GetDriveFileStatisticsRespStatistics struct {
	Uv             int64 `json:"uv,omitempty"`               // 文档历史访问人数, 同一用户（user_id）多次访问按一次计算。
	Pv             int64 `json:"pv,omitempty"`               // 文档历史访问次数, 同一用户（user_id）多次访问按多次计算。（注: 同一用户相邻两次访问间隔在半小时内视为一次访问）
	LikeCount      int64 `json:"like_count,omitempty"`       // 文档历史点赞总数, 若对应的文档类型不支持点赞, 返回 -1
	Timestamp      int64 `json:"timestamp,omitempty"`        // 时间戳（秒）
	UvToday        int64 `json:"uv_today,omitempty"`         // 今日新增文档访问人数
	PvToday        int64 `json:"pv_today,omitempty"`         // 今日新增文档访问次数
	LikeCountToday int64 `json:"like_count_today,omitempty"` // 今日新增文档点赞数
}

// getDriveFileStatisticsResp ...
type getDriveFileStatisticsResp struct {
	Code int64                       `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                      `json:"msg,omitempty"`  // 错误描述
	Data *GetDriveFileStatisticsResp `json:"data,omitempty"`
}
