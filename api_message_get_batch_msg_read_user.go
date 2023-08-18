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

// GetBatchSentMessageReadUser 发送批量消息请求后, 可以通过该接口查询批量消息推送的总人数和阅读人数。
//
// 注意事项:
// - 只能查询30天内通过[批量发送消息](https://open.feishu.cn/document/ukTMukTMukTM/ucDO1EjL3gTNx4yN4UTM)接口产生的消息
// - 该接口返回的数据为查询时刻的快照数据
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/batch_message/read_user
// new doc: https://open.feishu.cn/document/server-docs/im-v1/batch_message/read_user
func (r *MessageService) GetBatchSentMessageReadUser(ctx context.Context, request *GetBatchSentMessageReadUserReq, options ...MethodOptionFunc) (*GetBatchSentMessageReadUserResp, *Response, error) {
	if r.cli.mock.mockMessageGetBatchSentMessageReadUser != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Message#GetBatchSentMessageReadUser mock enable")
		return r.cli.mock.mockMessageGetBatchSentMessageReadUser(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Message",
		API:                   "GetBatchSentMessageReadUser",
		Method:                "GET",
		URL:                   r.cli.openBaseURL + "/open-apis/im/v1/batch_messages/:batch_message_id/read_user",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
	}
	resp := new(getBatchSentMessageReadUserResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockMessageGetBatchSentMessageReadUser mock MessageGetBatchSentMessageReadUser method
func (r *Mock) MockMessageGetBatchSentMessageReadUser(f func(ctx context.Context, request *GetBatchSentMessageReadUserReq, options ...MethodOptionFunc) (*GetBatchSentMessageReadUserResp, *Response, error)) {
	r.mockMessageGetBatchSentMessageReadUser = f
}

// UnMockMessageGetBatchSentMessageReadUser un-mock MessageGetBatchSentMessageReadUser method
func (r *Mock) UnMockMessageGetBatchSentMessageReadUser() {
	r.mockMessageGetBatchSentMessageReadUser = nil
}

// GetBatchSentMessageReadUserReq ...
type GetBatchSentMessageReadUserReq struct {
	BatchMessageID string `path:"batch_message_id" json:"-"` // 待查询的批量消息任务 ID, 通过调用[批量发送消息接口](	/ssl:ttdoc/ukTMukTMukTM/ucDO1EjL3gTNx4yN4UTM)的返回值`message_id`中得到, 示例值: "bm_dc13264520392913993dd051dba21dcf"
}

// GetBatchSentMessageReadUserResp ...
type GetBatchSentMessageReadUserResp struct {
	ReadUser *GetBatchSentMessageReadUserRespReadUser `json:"read_user,omitempty"` // 批量发送消息的用户阅读情况
}

// GetBatchSentMessageReadUserRespReadUser ...
type GetBatchSentMessageReadUserRespReadUser struct {
	ReadCount  string `json:"read_count,omitempty"`  // 已读的人数
	TotalCount int64  `json:"total_count,omitempty"` // 推送的总人数
}

// getBatchSentMessageReadUserResp ...
type getBatchSentMessageReadUserResp struct {
	Code int64                            `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                           `json:"msg,omitempty"`  // 错误描述
	Data *GetBatchSentMessageReadUserResp `json:"data,omitempty"`
}
