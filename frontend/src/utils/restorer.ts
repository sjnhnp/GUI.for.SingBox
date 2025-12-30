import * as Defaults from '@/constant/profile'
import { Inbound, Outbound, RuleAction, RuleType, RulesetType, RulesetFormat, Strategy, TunStack, DnsServer } from '@/enums/kernel'

import { deepAssign, sampleID } from './others'

/**
 * 从 sing-box 原始配置恢复为 GUI Profile 格式
 * 用于订阅导入完整配置时使用
 */
export const restoreProfile = (config: Recordable, options?: { id?: string; name?: string }) => {
  const profile: IProfile = {
    id: options?.id || sampleID(),
    name: options?.name || sampleID(),
    log: Defaults.DefaultLog(),
    experimental: Defaults.DefaultExperimental(),
    inbounds: [],
    outbounds: [],
    route: {
      rule_set: [],
      rules: [],
      auto_detect_interface: true,
      find_process: false,
      default_interface: '',
      final: '',
      default_domain_resolver: {
        server: '',
        client_subnet: '',
      },
    },
    dns: {
      servers: [],
      rules: [],
      disable_cache: false,
      disable_expire: false,
      independent_cache: false,
      client_subnet: '',
      final: '',
      strategy: Strategy.Default,
    },
    mixin: Defaults.DefaultMixin(),
    script: Defaults.DefaultScript(),
  }

  // 创建 ID 映射表
  const InboundsIds: Record<string, string> = {}
  const OutboundsIds: Record<string, string> = {}
  const RulesetIds: Record<string, string> = {}
  const DnsServersIds: Record<string, string> = {}

  // 第一遍：收集所有 tag 并生成 ID
  if (config.inbounds) {
    config.inbounds.forEach((item: any) => {
      if (item.tag) InboundsIds[item.tag] = sampleID()
    })
  }
  if (config.outbounds) {
    config.outbounds.forEach((item: any) => {
      if (item.tag) OutboundsIds[item.tag] = sampleID()
    })
  }
  if (config.route?.rule_set) {
    config.route.rule_set.forEach((item: any) => {
      if (item.tag) RulesetIds[item.tag] = sampleID()
    })
  }
  if (config.dns?.servers) {
    config.dns.servers.forEach((item: any) => {
      if (item.tag) DnsServersIds[item.tag] = sampleID()
    })
  }

  // 处理各个配置部分
  Object.entries(config).forEach(([field, value]) => {
    if (field === 'log') {
      deepAssign(profile.log, value)
    } else if (field === 'experimental') {
      deepAssign(profile.experimental, value)
    } else if (field === 'inbounds') {
      profile.inbounds = (value as any[]).flatMap((inbound: any) => {
        // 只处理 GUI 支持的入站类型
        if (![Inbound.Http, Inbound.Mixed, Inbound.Socks, Inbound.Tun].includes(inbound.type)) {
          return []
        }
        const extra = {
          id: InboundsIds[inbound.tag] || sampleID(),
          tag: inbound.tag,
          type: inbound.type,
          enable: true,
        }
        if (inbound.type === Inbound.Tun) {
          return {
            ...extra,
            tun: {
              interface_name: inbound.interface_name || '',
              address: inbound.address || ['172.18.0.1/30', 'fdfe:dcba:9876::1/126'],
              mtu: inbound.mtu || 0,
              auto_route: !!inbound.auto_route,
              strict_route: !!inbound.strict_route,
              route_address: inbound.route_address || [],
              route_exclude_address: inbound.route_exclude_address || [],
              endpoint_independent_nat: !!inbound.endpoint_independent_nat,
              stack: inbound.stack || TunStack.Mixed,
            },
          }
        }
        if ([Inbound.Mixed, Inbound.Http, Inbound.Socks].includes(inbound.type)) {
          return {
            ...extra,
            [inbound.type]: {
              listen: {
                listen: inbound.listen || '127.0.0.1',
                listen_port: inbound.listen_port || 7890,
                tcp_fast_open: !!inbound.tcp_fast_open,
                tcp_multi_path: !!inbound.tcp_multi_path,
                udp_fragment: !!inbound.udp_fragment,
              },
              users: (inbound.users || []).map((user: any) => user.username + ':' + user.password),
            },
          }
        }
        return []
      })
    } else if (field === 'outbounds') {
      profile.outbounds = (value as any[]).flatMap((outbound: any) => {
        // 只处理 GUI 支持的出站类型（selector/urltest/direct/block）
        if (
          ![Outbound.Selector, Outbound.Direct, Outbound.Block, Outbound.Urltest].includes(
            outbound.type,
          )
        ) {
          return []
        }
        const extra: Recordable = Defaults.DefaultOutbound()
        extra.id = OutboundsIds[outbound.tag] || sampleID()
        extra.tag = outbound.tag
        extra.type = outbound.type

        // 处理出站引用
        if (outbound.outbounds) {
          extra.outbounds = outbound.outbounds.flatMap((tag: string) => {
            // 如果是内置类型，直接引用
            if (['direct', 'block'].includes(tag)) {
              return { id: tag, type: 'Built-in', tag }
            }
            // 如果是策略组引用
            if (OutboundsIds[tag]) {
              return { id: OutboundsIds[tag], type: 'Built-in', tag }
            }
            // 否则可能是代理节点（将在订阅中处理）
            return []
          })
        }

        // 处理 urltest 特有属性
        if (outbound.type === Outbound.Urltest) {
          extra.url = outbound.url || extra.url
          extra.interval = outbound.interval || extra.interval
          extra.tolerance = outbound.tolerance || extra.tolerance
        }
        extra.interrupt_exist_connections = outbound.interrupt_exist_connections ?? true

        return extra
      })
    } else if (field === 'route') {
      const routeValue = value as any

      // 处理 route 基本属性
      profile.route.auto_detect_interface = routeValue.auto_detect_interface ?? true
      profile.route.default_interface = routeValue.default_interface || ''
      profile.route.find_process = routeValue.find_process || false

      // 处理 final 出站
      if (routeValue.final) {
        profile.route.final = OutboundsIds[routeValue.final] || routeValue.final
      }

      // 处理 default_domain_resolver
      if (routeValue.default_domain_resolver) {
        const resolver = routeValue.default_domain_resolver
        profile.route.default_domain_resolver = {
          server: DnsServersIds[resolver.server] || resolver.server || '',
          client_subnet: resolver.client_subnet || '',
        }
      }

      // 处理 rule_set
      if (routeValue.rule_set) {
        profile.route.rule_set = routeValue.rule_set.map((ruleset: any) => {
          const id = RulesetIds[ruleset.tag] || sampleID()
          return {
            id,
            type: ruleset.type || RulesetType.Remote,
            tag: ruleset.tag,
            format: ruleset.format || RulesetFormat.Binary,
            url: ruleset.url || '',
            download_detour: OutboundsIds[ruleset.download_detour] || ruleset.download_detour || '',
            update_interval: ruleset.update_interval || '',
            path: ruleset.path || '',
            rules: '',
          }
        })
      }

      // 处理 rules
      if (routeValue.rules) {
        profile.route.rules = routeValue.rules.flatMap((rule: any) => {
          const id = sampleID()
          const baseRule: Recordable = {
            id,
            enable: true,
            invert: rule.invert || false,
            action: rule.action || RuleAction.Route,
            outbound: '',
            sniffer: [],
            strategy: Strategy.Default,
            server: '',
          }

          // 确定规则类型和载荷
          let ruleType: string = RuleType.Inline
          let payload = ''

          // 处理简单规则类型
          const simpleRuleTypes = [
            'inbound', 'network', 'protocol', 'domain', 'domain_suffix',
            'domain_keyword', 'domain_regex', 'source_ip_cidr', 'ip_cidr',
            'source_port', 'source_port_range', 'port', 'port_range',
            'process_name', 'process_path', 'process_path_regex', 'clash_mode',
          ]

          for (const type of simpleRuleTypes) {
            if (rule[type]) {
              ruleType = type
              payload = Array.isArray(rule[type]) ? rule[type].join(',') : String(rule[type])
              break
            }
          }

          // 处理 rule_set
          if (rule.rule_set) {
            ruleType = 'rule_set'
            const ruleSetTags = Array.isArray(rule.rule_set) ? rule.rule_set : [rule.rule_set]
            payload = ruleSetTags.map((tag: string) => RulesetIds[tag] || tag).join(',')
          }

          // 处理 ip_is_private
          if (rule.ip_is_private !== undefined) {
            ruleType = 'ip_is_private'
            payload = String(rule.ip_is_private)
          }

          baseRule.type = ruleType
          baseRule.payload = payload

          // 处理动作相关属性
          if (rule.action === 'route' || !rule.action) {
            baseRule.outbound = OutboundsIds[rule.outbound] || rule.outbound || ''
          } else if (rule.action === 'sniff') {
            baseRule.sniffer = rule.sniffer || []
          } else if (rule.action === 'resolve') {
            baseRule.strategy = rule.strategy || Strategy.Default
            baseRule.server = DnsServersIds[rule.server] || rule.server || ''
          }

          return baseRule
        })
      }
    } else if (field === 'dns') {
      const dnsValue = value as any

      profile.dns.disable_cache = dnsValue.disable_cache ?? false
      profile.dns.disable_expire = dnsValue.disable_expire ?? false
      profile.dns.independent_cache = dnsValue.independent_cache ?? false
      profile.dns.client_subnet = dnsValue.client_subnet || ''
      profile.dns.final = DnsServersIds[dnsValue.final] || dnsValue.final || ''
      profile.dns.strategy = dnsValue.strategy || Strategy.Default

      // 处理 DNS servers
      if (dnsValue.servers) {
        profile.dns.servers = dnsValue.servers.map((server: any) => {
          const id = DnsServersIds[server.tag] || sampleID()
          return {
            id,
            tag: server.tag || '',
            type: server.type || DnsServer.Udp,
            detour: OutboundsIds[server.detour] || server.detour || '',
            domain_resolver: DnsServersIds[server.domain_resolver] || server.domain_resolver || '',
            server: server.address || server.server || '',
            server_port: String(server.address_port || server.server_port || ''),
            path: server.path || '',
            interface: server.interface || '',
            inet4_range: server.inet4_range || '',
            inet6_range: server.inet6_range || '',
            hosts_path: server.hosts_path || [],
            predefined: server.predefined || {},
          }
        })
      }

      // 处理 DNS rules
      if (dnsValue.rules) {
        profile.dns.rules = dnsValue.rules.flatMap((rule: any) => {
          const id = sampleID()
          const baseRule: Recordable = {
            id,
            enable: true,
            invert: rule.invert || false,
            action: rule.action || RuleAction.Route,
            server: DnsServersIds[rule.server] || rule.server || '',
            strategy: rule.strategy || Strategy.Default,
            disable_cache: rule.disable_cache || false,
            client_subnet: rule.client_subnet || '',
          }

          // 确定规则类型和载荷
          let ruleType: string = RuleType.Inline
          let payload = ''

          const simpleRuleTypes = [
            'inbound', 'network', 'protocol', 'domain', 'domain_suffix',
            'domain_keyword', 'domain_regex', 'source_ip_cidr', 'ip_cidr',
            'source_port', 'source_port_range', 'port', 'port_range',
            'process_name', 'process_path', 'process_path_regex', 'clash_mode',
          ]

          for (const type of simpleRuleTypes) {
            if (rule[type]) {
              ruleType = type
              payload = Array.isArray(rule[type]) ? rule[type].join(',') : String(rule[type])
              break
            }
          }

          if (rule.rule_set) {
            ruleType = 'rule_set'
            const ruleSetTags = Array.isArray(rule.rule_set) ? rule.rule_set : [rule.rule_set]
            payload = ruleSetTags.map((tag: string) => RulesetIds[tag] || tag).join(',')
          }

          baseRule.type = ruleType
          baseRule.payload = payload

          return baseRule
        })
      }
    }
  })

  return profile
}

/**
 * 从订阅配置中提取代理节点
 * 返回需要被节点转换插件处理的原始代理列表
 */
export const extractProxiesFromConfig = (config: Recordable): Record<string, any>[] => {
  if (!config.outbounds) return []

  // 过滤出非策略组的代理节点
  const groupTypes = ['selector', 'urltest', 'direct', 'block', 'dns']
  return config.outbounds.filter((outbound: any) => !groupTypes.includes(outbound.type))
}

/**
 * 获取策略组中对代理节点的引用关系
 * 用于在 Profile 的出站中引用订阅的代理
 */
export const getProxyReferencesFromConfig = (config: Recordable): Map<string, string[]> => {
  const references = new Map<string, string[]>()
  if (!config.outbounds) return references

  const groupTypes = ['selector', 'urltest']

  config.outbounds.forEach((outbound: any) => {
    if (groupTypes.includes(outbound.type) && outbound.outbounds) {
      // 过滤出代理节点的引用
      const proxyRefs = outbound.outbounds.filter((tag: string) => {
        const target = config.outbounds.find((o: any) => o.tag === tag)
        return target && !['selector', 'urltest', 'direct', 'block', 'dns'].includes(target.type)
      })
      if (proxyRefs.length > 0) {
        references.set(outbound.tag, proxyRefs)
      }
    }
  })

  return references
}

