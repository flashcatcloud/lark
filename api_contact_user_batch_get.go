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

// BatchGetUserByID 通过该接口, 可使用手机号/邮箱获取用户的 ID 信息, 具体获取支持的 ID 类型包括 open_id、user_id、union_id, 可通过查询参数指定。
//
// 如果查询的手机号、邮箱不存在, 或者无权限查看对应的用户, 则返回的open_id为空。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/contact-v3/user/batch_get_id
func (r *ContactService) BatchGetUserByID(ctx context.Context, request *BatchGetUserByIDReq, options ...MethodOptionFunc) (*BatchGetUserByIDResp, *Response, error) {
	if r.cli.mock.mockContactBatchGetUserByID != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Contact#BatchGetUserByID mock enable")
		return r.cli.mock.mockContactBatchGetUserByID(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Contact",
		API:                   "BatchGetUserByID",
		Method:                "POST",
		URL:                   r.cli.openBaseURL + "/open-apis/contact/v3/users/batch_get_id",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(batchGetUserByIDResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockContactBatchGetUserByID mock ContactBatchGetUserByID method
func (r *Mock) MockContactBatchGetUserByID(f func(ctx context.Context, request *BatchGetUserByIDReq, options ...MethodOptionFunc) (*BatchGetUserByIDResp, *Response, error)) {
	r.mockContactBatchGetUserByID = f
}

// UnMockContactBatchGetUserByID un-mock ContactBatchGetUserByID method
func (r *Mock) UnMockContactBatchGetUserByID() {
	r.mockContactBatchGetUserByID = nil
}

// BatchGetUserByIDReq ...
type BatchGetUserByIDReq struct {
	UserIDType *IDType  `query:"user_id_type" json:"-"` // 用户 ID 类型, 示例值: "open_id", 可选值有: `open_id`: 用户的 open id, `union_id`: 用户的 union id, `user_id`: 用户的 user id, 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
	Emails     []string `json:"emails,omitempty"`       // 要查询的用户邮箱, 最多 50 条, 示例值: zhangsan@a.com, 最大长度: `50`
	Mobiles    []string `json:"mobiles,omitempty"`      // 要查询的用户手机号, 最多 50 条。 非中国大陆地区的手机号需要添加以 “+” 开头的国家 / 地区代码, 示例值: 13812345678, 最大长度: `50`
}

// BatchGetUserByIDResp ...
type BatchGetUserByIDResp struct {
	UserList []*BatchGetUserByIDRespUser `json:"user_list,omitempty"` // 手机号或者邮箱对应的用户id信息
}

// BatchGetUserByIDRespUser ...
type BatchGetUserByIDRespUser struct {
	UserID string `json:"user_id,omitempty"` // 用户id, 值为user_id_type所指定的类型。如果查询的手机号、邮箱不存在, 或者无权限查看对应的用户, 则此项为空。
	Mobile string `json:"mobile,omitempty"`  // 手机号, 通过手机号查询时返回
	Email  string `json:"email,omitempty"`   // 邮箱, 通过邮箱查询时返回
}

// batchGetUserByIDResp ...
type batchGetUserByIDResp struct {
	Code int64                 `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                `json:"msg,omitempty"`  // 错误描述
	Data *BatchGetUserByIDResp `json:"data,omitempty"`
}