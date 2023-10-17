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

// CreateLingoDraft 草稿并非词条, 而是指通过 API 发起创建新词条或更新现有词条的申请。
//
// 词典管理员审核通过后, 草稿将变为新的词条或覆盖已有词条。
// - 创建新的词条时, 无需传入 entity_id 字段
// - 更新已有词条时, 请传入对应词条的 entity_id 或 outer_info
// 以用户身份创建草稿（即 Authorization 使用 user_access_token）, 对应用户将收到由飞书词典 Bot 发送的审核结果；以应用身份创建草稿（即 Authorization 使用 tenant_access_toke）, 不会收到任何通知。
//
// doc: https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/lingo-v1/draft/create
func (r *LingoService) CreateLingoDraft(ctx context.Context, request *CreateLingoDraftReq, options ...MethodOptionFunc) (*CreateLingoDraftResp, *Response, error) {
	if r.cli.mock.mockLingoCreateLingoDraft != nil {
		r.cli.log(ctx, LogLevelDebug, "[lark] Lingo#CreateLingoDraft mock enable")
		return r.cli.mock.mockLingoCreateLingoDraft(ctx, request, options...)
	}

	req := &RawRequestReq{
		Scope:                 "Lingo",
		API:                   "CreateLingoDraft",
		Method:                "POST",
		URL:                   r.cli.openBaseURL + "/open-apis/lingo/v1/drafts",
		Body:                  request,
		MethodOption:          newMethodOption(options),
		NeedTenantAccessToken: true,
		NeedUserAccessToken:   true,
	}
	resp := new(createLingoDraftResp)

	response, err := r.cli.RawRequest(ctx, req, resp)
	return resp.Data, response, err
}

// MockLingoCreateLingoDraft mock LingoCreateLingoDraft method
func (r *Mock) MockLingoCreateLingoDraft(f func(ctx context.Context, request *CreateLingoDraftReq, options ...MethodOptionFunc) (*CreateLingoDraftResp, *Response, error)) {
	r.mockLingoCreateLingoDraft = f
}

// UnMockLingoCreateLingoDraft un-mock LingoCreateLingoDraft method
func (r *Mock) UnMockLingoCreateLingoDraft() {
	r.mockLingoCreateLingoDraft = nil
}

// CreateLingoDraftReq ...
type CreateLingoDraftReq struct {
	RepoID      *string                         `query:"repo_id" json:"-"`      // 词库ID（需要在指定词库创建草稿时填写, 不填写默认创建至全员词库）, 如以应用身份创建草稿到非全员词库, 需要在“词库设置”页面添加应用；若以用户身份创建草稿到非全员词库, 该用户需要拥有对应词库的可见权限, 示例值: 72025640276
	UserIDType  *IDType                         `query:"user_id_type" json:"-"` // 用户 ID 类型, 示例值: open_id, 可选值有: open_id: 标识一个用户在某个应用中的身份。同一个用户在不同应用中的 Open ID 不同。[了解更多: 如何获取 Open ID](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-openid), union_id: 标识一个用户在某个应用开发商下的身份。同一用户在同一开发商下的应用中的 Union ID 是相同的, 在不同开发商下的应用中的 Union ID 是不同的。通过 Union ID, 应用开发商可以把同个用户在多个应用中的身份关联起来。[了解更多: 如何获取 Union ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-union-id), user_id: 标识一个用户在某个租户内的身份。同一个用户在租户 A 和租户 B 内的 User ID 是不同的。在同一个租户内, 一个用户的 User ID 在所有应用（包括商店应用）中都保持一致。User ID 主要用于在不同的应用间打通用户数据。[了解更多: 如何获取 User ID？](https://open.feishu.cn/document/uAjLw4CM/ugTN1YjL4UTN24CO1UjN/trouble-shooting/how-to-obtain-user-id), 默认值: `open_id`, 当值为 `user_id`, 字段权限要求: 获取用户 user ID
	ID          *string                         `json:"id,omitempty"`           // 词条 ID （需要更新某个词条时填写, 若是创建新词条可不填写）, 示例值: "enterprise_40217521"
	MainKeys    []*CreateLingoDraftReqMainKey   `json:"main_keys,omitempty"`    // 词条名, 最大长度: `1`
	Aliases     []*CreateLingoDraftReqAliase    `json:"aliases,omitempty"`      // 别名, 最大长度: `10`
	Description *string                         `json:"description,omitempty"`  // 纯文本格式词条释义。注: description 和 rich_text 至少有一个, 否则会报错: 1540001, 示例值: "词典是飞书提供的一款知识管理工具, 通过飞书词典可以帮助企业将分散的知识信息进行聚合, 并通过UGC的方式, 促进企业知识的保鲜和流通", 最大长度: `5000` 字符
	RelatedMeta *CreateLingoDraftReqRelatedMeta `json:"related_meta,omitempty"` // 词条相关信息
	OuterInfo   *CreateLingoDraftReqOuterInfo   `json:"outer_info,omitempty"`   // 外部系统关联数据
	RichText    *string                         `json:"rich_text,omitempty"`    // 富文本格式（当填写富文本内容时, description字段将会失效可不填写）, 支持的格式参考[企业百科指南](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/baike-v1/overview)中的释义部分, 示例值: "<b>加粗</b><i>斜体</i><p><a href="https://feishu.cn">l链接</a></p><p><span>企业百科是飞书提供的一款知识管理工具, 通过企业百科可以帮助企业将分散的知识信息进行聚合, 并通过UGC的方式, 促进企业知识的保鲜和流通</span></p>", 最大长度: `5000` 字符
	I18nDescs   []*CreateLingoDraftReqI18nDesc  `json:"i18n_descs,omitempty"`   // 国际化的词条释义, 最大长度: `3`
}

// CreateLingoDraftReqAliase ...
type CreateLingoDraftReqAliase struct {
	Key           string                                  `json:"key,omitempty"`            // 名称的值, 示例值: "飞书词典"
	DisplayStatus *CreateLingoDraftReqAliaseDisplayStatus `json:"display_status,omitempty"` // 名称的展示范围
}

// CreateLingoDraftReqAliaseDisplayStatus ...
type CreateLingoDraftReqAliaseDisplayStatus struct {
	AllowHighlight bool `json:"allow_highlight,omitempty"` // 是否允许在 IM 和 Doc 等场景进行高亮提示, 示例值: true
	AllowSearch    bool `json:"allow_search,omitempty"`    // 是否允许在飞书中被搜索到, 示例值: true
}

// CreateLingoDraftReqI18nDesc ...
type CreateLingoDraftReqI18nDesc struct {
	Language    int64   `json:"language,omitempty"`    // 语言类型, 示例值: 1, 可选值有: 1: 中文, 2: 英文, 3: 日文
	Description *string `json:"description,omitempty"` // 纯文本释义, 示例值: "词典是飞书提供的一款知识管理工具, 通过飞书词典可以帮助企业将分散的知识信息进行聚合, 并通过UGC的方式, 促进企业知识的保鲜和流通", 长度范围: `1` ～ `5000` 字符
	RichText    *string `json:"rich_text,omitempty"`   // 富文本描述, 示例值: "<b>加粗</b><i>斜体</i><p><a href="https://feishu.cn">l链接</a></p><p><span>企业百科是飞书提供的一款知识管理工具, 通过企业百科可以帮助企业将分散的知识信息进行聚合, 并通过UGC的方式, 促进企业知识的保鲜和流通</span></p>", 长度范围: `1` ～ `5000` 字符
}

// CreateLingoDraftReqMainKey ...
type CreateLingoDraftReqMainKey struct {
	Key           string                                   `json:"key,omitempty"`            // 名称, 示例值: "飞书词典"
	DisplayStatus *CreateLingoDraftReqMainKeyDisplayStatus `json:"display_status,omitempty"` // 名称的展示范围
}

// CreateLingoDraftReqMainKeyDisplayStatus ...
type CreateLingoDraftReqMainKeyDisplayStatus struct {
	AllowHighlight bool `json:"allow_highlight,omitempty"` // 是否允许在 IM 和 Doc 等场景进行高亮提示, 示例值: true
	AllowSearch    bool `json:"allow_search,omitempty"`    // 是否允许在飞书中被搜索到, 示例值: true
}

// CreateLingoDraftReqOuterInfo ...
type CreateLingoDraftReqOuterInfo struct {
	Provider string `json:"provider,omitempty"` // 数据提供方（不能包含中横线 "-"）, 示例值: "星云", 长度范围: `2` ～ `32` 字符
	OuterID  string `json:"outer_id,omitempty"` // 唯一标识, 可用来和其他平台的内容进行绑定。需保证和百科词条唯一对应（不能包含中横线 "-"）, 示例值: "12345abc", 长度范围: `1` ～ `64` 字符
}

// CreateLingoDraftReqRelatedMeta ...
type CreateLingoDraftReqRelatedMeta struct {
	Users           []*CreateLingoDraftReqRelatedMetaUser           `json:"users,omitempty"`           // 相关联系人
	Chats           []*CreateLingoDraftReqRelatedMetaChat           `json:"chats,omitempty"`           // 相关公开群
	Docs            []*CreateLingoDraftReqRelatedMetaDoc            `json:"docs,omitempty"`            // 飞书文档或飞书 wiki
	Oncalls         []*CreateLingoDraftReqRelatedMetaOncall         `json:"oncalls,omitempty"`         // 飞书值班号
	Links           []*CreateLingoDraftReqRelatedMetaLink           `json:"links,omitempty"`           // 其他网页链接
	Abbreviations   []*CreateLingoDraftReqRelatedMetaAbbreviation   `json:"abbreviations,omitempty"`   // 相关词条
	Classifications []*CreateLingoDraftReqRelatedMetaClassification `json:"classifications,omitempty"` // 当前词条所属分类, 词条只能属于二级分类, 且每个一级分类下只能选择一个二级分类。
	Images          []*CreateLingoDraftReqRelatedMetaImage          `json:"images,omitempty"`          // 上传的相关图片, 最大长度: `10`
}

// CreateLingoDraftReqRelatedMetaAbbreviation ...
type CreateLingoDraftReqRelatedMetaAbbreviation struct {
	ID *string `json:"id,omitempty"` // 其他相关词条 id, 示例值: "enterprise_5158***7960"
}

// CreateLingoDraftReqRelatedMetaChat ...
type CreateLingoDraftReqRelatedMetaChat struct {
	ID string `json:"id,omitempty"` // 公开群 id, 示例值: "oc_c13831833eaa8c92***cfa759ea4806"
}

// CreateLingoDraftReqRelatedMetaClassification ...
type CreateLingoDraftReqRelatedMetaClassification struct {
	ID       string  `json:"id,omitempty"`        // 二级分类 ID, 示例值: "704960692637761"
	FatherID *string `json:"father_id,omitempty"` // 对应一级分类 ID, 示例值: "704960692637777"
}

// CreateLingoDraftReqRelatedMetaDoc ...
type CreateLingoDraftReqRelatedMetaDoc struct {
	Title *string `json:"title,omitempty"` // 文档标题, 示例值: "快速了解飞书文档"
	URL   *string `json:"url,omitempty"`   // 文档 url, 示例值: "https://example.feishu.cn/docs/doccnxlVCs***sJE15I7PLAjIWc", 正则校验: `(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:.;]+[-A-Za-z0-9+&@#/%=~_|]`
}

// CreateLingoDraftReqRelatedMetaImage ...
type CreateLingoDraftReqRelatedMetaImage struct {
	Token string `json:"token,omitempty"` // 通过文件接口上传图片后, 获得的图片 token, 示例值: "boxbcEcmKiDia3e***WTpvdc7jc"
}

// CreateLingoDraftReqRelatedMetaLink ...
type CreateLingoDraftReqRelatedMetaLink struct {
	Title *string `json:"title,omitempty"` // 标题, 示例值: "飞书官网"
	URL   *string `json:"url,omitempty"`   // 链接地址, 示例值: "https://feishu.cn", 正则校验: `(https?|ftp|file)://[-A-Za-z0-9+&@#/%?=~_|!:.;]+[-A-Za-z0-9+&@#/%=~_|]`
}

// CreateLingoDraftReqRelatedMetaOncall ...
type CreateLingoDraftReqRelatedMetaOncall struct {
	ID string `json:"id,omitempty"` // 值班号 id, 示例值: "70236890***45548034"
}

// CreateLingoDraftReqRelatedMetaUser ...
type CreateLingoDraftReqRelatedMetaUser struct {
	ID    string  `json:"id,omitempty"`    // 格式根据 user_id_type 不同需要符合 open_id、user_id、union_id 格式的有效 id, 示例值: "ou_30b07b63089e***18789914dac63d36"
	Title *string `json:"title,omitempty"` // 备注, 示例值: "xxx 负责人"
}

// CreateLingoDraftResp ...
type CreateLingoDraftResp struct {
	Draft *CreateLingoDraftRespDraft `json:"draft,omitempty"` // 草稿信息
}

// CreateLingoDraftRespDraft ...
type CreateLingoDraftRespDraft struct {
	DraftID string                           `json:"draft_id,omitempty"` // 草稿 ID
	Entity  *CreateLingoDraftRespDraftEntity `json:"entity,omitempty"`   // 词条信息
}

// CreateLingoDraftRespDraftEntity ...
type CreateLingoDraftRespDraftEntity struct {
	ID          string                                      `json:"id,omitempty"`           // 词条 ID
	MainKeys    []*CreateLingoDraftRespDraftEntityMainKey   `json:"main_keys,omitempty"`    // 词条名
	Aliases     []*CreateLingoDraftRespDraftEntityAliase    `json:"aliases,omitempty"`      // 别名
	Description string                                      `json:"description,omitempty"`  // 纯文本格式词条释义。注: description 和 rich_text 至少有一个, 否则会报错: 1540001
	Creator     string                                      `json:"creator,omitempty"`      // 词条创建时间
	CreateTime  string                                      `json:"create_time,omitempty"`  // 词条创建时间（秒级时间戳）
	Updater     string                                      `json:"updater,omitempty"`      // 最近一次更新者
	UpdateTime  string                                      `json:"update_time,omitempty"`  // 最近一次更新词条时间（秒级时间戳）
	RelatedMeta *CreateLingoDraftRespDraftEntityRelatedMeta `json:"related_meta,omitempty"` // 相关数据
	Statistics  *CreateLingoDraftRespDraftEntityStatistics  `json:"statistics,omitempty"`   // 统计数据
	OuterInfo   *CreateLingoDraftRespDraftEntityOuterInfo   `json:"outer_info,omitempty"`   // 外部 id 关联数据
	RichText    string                                      `json:"rich_text,omitempty"`    // 富文本格式（当填写富文本内容时, description字段将会失效可不填写）, 支持的格式参考[企业百科指南](https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/baike-v1/overview)中的释义部分
	Source      int64                                       `json:"source,omitempty"`       // 词条的创建来源, 1: 用户主动创建, 2: 批量导入, 3: 官方词, 4: OpenAPI 创建
	I18nDescs   []*CreateLingoDraftRespDraftEntityI18nDesc  `json:"i18n_descs,omitempty"`   // 国际化的词条释义
}

// CreateLingoDraftRespDraftEntityAliase ...
type CreateLingoDraftRespDraftEntityAliase struct {
	Key           string                                              `json:"key,omitempty"`            // 名称的值
	DisplayStatus *CreateLingoDraftRespDraftEntityAliaseDisplayStatus `json:"display_status,omitempty"` // 名称展示范围
}

// CreateLingoDraftRespDraftEntityAliaseDisplayStatus ...
type CreateLingoDraftRespDraftEntityAliaseDisplayStatus struct {
	AllowHighlight bool `json:"allow_highlight,omitempty"` // 是否允许在 IM 和 Doc 等场景进行高亮提示
	AllowSearch    bool `json:"allow_search,omitempty"`    // 是否允许在飞书中被搜索到
}

// CreateLingoDraftRespDraftEntityI18nDesc ...
type CreateLingoDraftRespDraftEntityI18nDesc struct {
	Language    int64  `json:"language,omitempty"`    // 语言类型, 可选值有: 1: 中文, 2: 英文, 3: 日文
	Description string `json:"description,omitempty"` // 纯文本释义
	RichText    string `json:"rich_text,omitempty"`   // 富文本描述
}

// CreateLingoDraftRespDraftEntityMainKey ...
type CreateLingoDraftRespDraftEntityMainKey struct {
	Key           string                                               `json:"key,omitempty"`            // 名称
	DisplayStatus *CreateLingoDraftRespDraftEntityMainKeyDisplayStatus `json:"display_status,omitempty"` // 名称展示范围
}

// CreateLingoDraftRespDraftEntityMainKeyDisplayStatus ...
type CreateLingoDraftRespDraftEntityMainKeyDisplayStatus struct {
	AllowHighlight bool `json:"allow_highlight,omitempty"` // 是否允许在 IM 和 Doc 等场景进行高亮提示
	AllowSearch    bool `json:"allow_search,omitempty"`    // 是否允许在飞书中被搜索到
}

// CreateLingoDraftRespDraftEntityOuterInfo ...
type CreateLingoDraftRespDraftEntityOuterInfo struct {
	Provider string `json:"provider,omitempty"` // 数据提供方（不能包含中横线 "-"）
	OuterID  string `json:"outer_id,omitempty"` // 唯一标识, 可用来和其他平台的内容进行绑定。需保证和百科词条唯一对应（不能包含中横线 "-"）
}

// CreateLingoDraftRespDraftEntityRelatedMeta ...
type CreateLingoDraftRespDraftEntityRelatedMeta struct {
	Users           []*CreateLingoDraftRespDraftEntityRelatedMetaUser           `json:"users,omitempty"`           // 关联用户信息
	Chats           []*CreateLingoDraftRespDraftEntityRelatedMetaChat           `json:"chats,omitempty"`           // 关联公开群组信息
	Docs            []*CreateLingoDraftRespDraftEntityRelatedMetaDoc            `json:"docs,omitempty"`            // 关联文档信息
	Oncalls         []*CreateLingoDraftRespDraftEntityRelatedMetaOncall         `json:"oncalls,omitempty"`         // 关联值班者信息
	Links           []*CreateLingoDraftRespDraftEntityRelatedMetaLink           `json:"links,omitempty"`           // 关联链接信息
	Abbreviations   []*CreateLingoDraftRespDraftEntityRelatedMetaAbbreviation   `json:"abbreviations,omitempty"`   // 相关词条信息
	Classifications []*CreateLingoDraftRespDraftEntityRelatedMetaClassification `json:"classifications,omitempty"` // 所属分类信息（不支持传入一级分类。词条不可同时属于同一个一级分类下的多个二级分类, 一级分类下的二级分类互斥）
	Images          []*CreateLingoDraftRespDraftEntityRelatedMetaImage          `json:"images,omitempty"`          // 上传的相关图片
}

// CreateLingoDraftRespDraftEntityRelatedMetaAbbreviation ...
type CreateLingoDraftRespDraftEntityRelatedMetaAbbreviation struct {
	ID string `json:"id,omitempty"` // 相关其他词条 id
}

// CreateLingoDraftRespDraftEntityRelatedMetaChat ...
type CreateLingoDraftRespDraftEntityRelatedMetaChat struct {
	ID    string `json:"id,omitempty"`    // 数据 id
	Title string `json:"title,omitempty"` // 标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// CreateLingoDraftRespDraftEntityRelatedMetaClassification ...
type CreateLingoDraftRespDraftEntityRelatedMetaClassification struct {
	ID       string `json:"id,omitempty"`        // 唯一分类 ID
	FatherID string `json:"father_id,omitempty"` // 父级分类的 ID
}

// CreateLingoDraftRespDraftEntityRelatedMetaDoc ...
type CreateLingoDraftRespDraftEntityRelatedMetaDoc struct {
	Title string `json:"title,omitempty"` // 标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// CreateLingoDraftRespDraftEntityRelatedMetaImage ...
type CreateLingoDraftRespDraftEntityRelatedMetaImage struct {
	Token string `json:"token,omitempty"` // 通过文件接口上传后的图片 token
}

// CreateLingoDraftRespDraftEntityRelatedMetaLink ...
type CreateLingoDraftRespDraftEntityRelatedMetaLink struct {
	Title string `json:"title,omitempty"` // 标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// CreateLingoDraftRespDraftEntityRelatedMetaOncall ...
type CreateLingoDraftRespDraftEntityRelatedMetaOncall struct {
	ID    string `json:"id,omitempty"`    // 数据 id
	Title string `json:"title,omitempty"` // 标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// CreateLingoDraftRespDraftEntityRelatedMetaUser ...
type CreateLingoDraftRespDraftEntityRelatedMetaUser struct {
	ID    string `json:"id,omitempty"`    // 数据 id
	Title string `json:"title,omitempty"` // 标题
	URL   string `json:"url,omitempty"`   // 链接地址
}

// CreateLingoDraftRespDraftEntityStatistics ...
type CreateLingoDraftRespDraftEntityStatistics struct {
	LikeCount    int64 `json:"like_count,omitempty"`    // 点赞数量
	DislikeCount int64 `json:"dislike_count,omitempty"` // 点踩数量
}

// createLingoDraftResp ...
type createLingoDraftResp struct {
	Code int64                 `json:"code,omitempty"` // 错误码, 非 0 表示失败
	Msg  string                `json:"msg,omitempty"`  // 错误描述
	Data *CreateLingoDraftResp `json:"data,omitempty"`
}
