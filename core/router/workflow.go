package router

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"
)

func workflow(ctx context.Context, m *management, r *Result, o Options, src source, label string, hh []header, verify func(context.Context, int, int) error, inlineMatches func(context.Context, string, string) bool) (Result, error) {
	st, err := getStatus(ctx, m)
	if err != nil {
		return *r, err
	}
	if !st.ProxyComponent {
		return *r, errors.New("Добавьте компонент «Клиент прокси» в KeeneticOS и повторите. Обновление прошивки мастер не запускает.")
	}
	if !*st.NDMSProxyEnabled {
		return *r, errors.New("В AWG Manager отключено создание NDMS Proxy. Включите его в настройках Sing-box после проверки влияния на имеющиеся туннели.")
	}
	var all []subscription
	if err = m.call(ctx, "GET", subscriptions, nil, &all, true); err != nil {
		return *r, err
	}
	var selected *subscription
	for i := range all {
		it := &all[i]
		match := src.url != "" && it.URL == src.url || src.inline != "" && it.IsInline && it.Label == label
		if !match {
			if it.Label == label {
				return *r, errors.New("Это имя уже занято другой подпиской. Выберите другое название.")
			}
			continue
		}
		if selected != nil {
			return *r, errors.New("Источник уже импортирован несколько раз. Выберите нужную запись в панели.")
		}
		if src.inline != "" && (inlineMatches == nil || !inlineMatches(ctx, it.ID, src.inline)) {
			return *r, errors.New("Существующая группа с таким названием содержит другой набор ключей. Выберите другое название.")
		}
		if len(hh) > 0 {
			existing := map[string]string{}
			for _, h := range it.Headers {
				existing[strings.ToLower(h.Name)] = h.Value
			}
			for _, h := range hh {
				if existing[strings.ToLower(h.Name)] != h.Value {
					return *r, errors.New("Источник уже существует с другими заголовками доступа. Проверьте эту подписку в панели.")
				}
			}
		}
		if it.Mode != "urltest" || !it.Enabled {
			return *r, errors.New("Такая подписка уже есть с другими настройками. Включите её и режим «Авто» в панели или выберите другой источник.")
		}
		if len(it.ExcludedTags) != 0 || it.FilterInclude != "" || it.FilterExclude != "" {
			return *r, errors.New("У существующей группы есть исключения или фильтры серверов. Чтобы включить всю подписку, снимите их в AWG Manager и повторите.")
		}
		selected = it
	}
	if !st.Running {
		others := len(all)
		if selected != nil {
			others--
		}
		if others > 0 || st.TunnelCount > 0 {
			return *r, errors.New("Движок остановлен и содержит другие подключения. Запустите его в панели, затем повторите импорт.")
		}
		var route struct{ Enabled *bool }
		if err = m.call(ctx, "GET", "/api/singbox/router/status", nil, &route, true); err != nil {
			return *r, err
		}
		if route.Enabled == nil || *route.Enabled {
			return *r, errors.New("Проверьте текущий режим маршрутизации и запустите установленный движок в панели.")
		}
	}
	if src.encrypted && selected == nil {
		var state struct{ Configured bool }
		if err = m.call(ctx, "GET", subscriptions+"/happ-keys", nil, &state, true); err != nil {
			return *r, err
		}
		if !state.Configured {
			return *r, errors.New("Для Happ Crypt нужны ключи расшифровки, настроенные владельцем в AWG Manager. Можно использовать обычный URL подписки.")
		}
	}
	var previewKeys map[string]bool
	if selected == nil && src.url != "" {
		var preview []member
		err = m.call(ctx, "POST", subscriptions+"/preview", map[string]any{"url": src.url, "headers": hh}, &preview, true)
		if err != nil {
			return *r, fmt.Errorf("Не удалось получить профили: проверьте доступ провайдера и требуемые им заголовки. %w", err)
		}
		previewKeys = make(map[string]bool, len(preview))
		for _, p := range preview {
			if p.Key == "" || p.Protocol == "" {
				return *r, errors.New("Панель не подтвердила идентификатор или протокол одного из серверов. Проверьте версию API.")
			}
			previewKeys[p.Key] = true
		}
		if len(previewKeys) < 2 {
			return *r, errors.New("AWG Manager распознал меньше двух разных серверов в ответе провайдера. Проверьте формат подписки и условия доступа.")
		}
	}
	if !st.Installed {
		if !o.InstallMissing {
			return *r, errors.New("Для импорта требуется движок Sing-box. Разрешите его установку в мастере.")
		}
		// v2.19.25 reports requiredSha256 only once a binary already exists.
		// Its architecture digests are embedded in the pinned panel; verify
		// currentSha256 against our independent copy immediately after install.
		digest := buildArch[r.Architecture]
		if strings.Split(r.PanelVersion, "-")[0] != "2.19.25" || st.RequiredVersion != "1.15.0-alpha.13-awgm.36" || digest == "" || (st.RequiredSHA256 != "" && st.RequiredSHA256 != digest) {
			return *r, errors.New("Для предложенного панелью движка нет проверенной суммы в этой версии мастера. Установите его штатно в AWG Manager и повторите.")
		}
		var installed status
		if err = m.call(ctx, "POST", "/api/singbox/install", nil, &installed, true); err != nil {
			return *r, err
		}
		st, err = getStatus(ctx, m)
		if err != nil {
			return *r, err
		}
		if !st.Installed || st.CurrentSHA256 != buildArch[r.Architecture] {
			return *r, errors.New("Панель не подтвердила контрольную сумму установленного движка.")
		}
		r.InstalledEngine = true
	}
	r.EngineVersion = st.CurrentVersion
	if r.EngineVersion == "" {
		r.EngineVersion = st.Version
	}
	if selected == nil {
		body := map[string]any{"label": label, "enabled": true, "mode": "urltest", "refreshHours": 1, "urlTest": map[string]any{"url": "https://www.gstatic.com/generate_204", "intervalSec": 60, "toleranceMs": 50}}
		if src.inline != "" {
			body["inline"] = src.inline
		} else {
			body["url"] = src.url
			body["headers"] = hh
		}
		var created subscription
		if err = m.call(ctx, "POST", subscriptions+"/create", body, &created, true); err != nil {
			return *r, fmt.Errorf("Импорт не подтверждён. При повторе мастер сверит существующие подписки. %w", err)
		}
		if created.ID == "" || created.Label != label {
			return *r, errors.New("Панель не подтвердила идентификатор созданной подписки. Проверьте список в AWG Manager.")
		}
		selected = &created
		r.Imported = true
	}
	if !automaticGroupVerified(selected) {
		if r.Imported {
			rollback, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if err = m.call(rollback, "DELETE", subscriptions+"/delete?id="+url.QueryEscape(selected.ID), nil, nil, true); err != nil {
				return *r, errors.New("Состав группы отличается от запроса. Не удалось удалить новую запись, проверьте её в панели.")
			}
			r.Imported = false
		}
		return *r, errors.New("AWG Manager не подтвердил автоматическую группу с двумя или более разными серверами. Проверьте формат подписки и протоколы на роутере.")
	}
	r.Group = selected.Label
	r.Profiles = len(selected.MemberTags)
	if selected.ProxyIndex == nil || *selected.ProxyIndex < 0 || *selected.ProxyIndex > 255 || selected.ListenPort < 1 || selected.ListenPort > 65535 {
		return *r, errors.New("Группа сохранена, но панель не подтверждает выделенный NDMS Proxy. Проверьте компонент и состояние панели.")
	}
	r.Proxy = fmt.Sprintf("Proxy%d", *selected.ProxyIndex)
	st, err = getStatus(ctx, m)
	if err != nil {
		return *r, err
	}
	if !st.Running {
		if err = m.call(ctx, "POST", "/api/singbox/control", map[string]string{"action": "start"}, nil, true); err != nil {
			return *r, errors.New("Группа сохранена, но служба не запущена. Проверьте статус Sing-box и повторите.")
		}
	}
	if err = verify(ctx, *selected.ProxyIndex, selected.ListenPort); err != nil {
		return *r, err
	}
	r.Message = fmt.Sprintf("Серверов в автоматической группе: %d. Проверочный HTTPS-запрос через группу прошёл.", r.Profiles)
	// AWG Manager fetches a URL once for preview and again during creation.
	// Each preview key is the provider-independent suffix of its stable tag.
	for _, tag := range selected.MemberTags {
		key, found := strings.CutPrefix(tag, selected.SelectorTag+"-")
		if found {
			delete(previewKeys, key)
		}
	}
	if len(previewKeys) > 0 {
		r.Message += fmt.Sprintf(" Серверов из предпросмотра, отсутствующих в созданной группе: %d. Проверьте состав подписки в панели.", len(previewKeys))
	}
	if src.inline != "" && src.count != r.Profiles {
		r.Message += fmt.Sprintf(" В исходном списке ссылок: %d. Фактический состав указан в AWG Manager.", src.count)
	}
	if n := len(selected.RejectedMembers); n > 0 {
		r.Message += fmt.Sprintf(" Отклонённых панелью записей: %d.", n)
	}
	return *r, nil
}

func automaticGroupVerified(group *subscription) bool {
	if group.SelectorTag == "" || !group.Enabled || group.Mode != "urltest" || len(group.MemberTags) < 2 || len(group.MemberTags) != len(group.Members) {
		return false
	}
	tags := make(map[string]bool, len(group.MemberTags))
	for _, tag := range group.MemberTags {
		if tag == "" || tags[tag] {
			return false
		}
		tags[tag] = true
	}
	for _, node := range group.Members {
		if !tags[node.Tag] || node.Protocol == "" {
			return false
		}
		delete(tags, node.Tag)
	}
	return true
}
