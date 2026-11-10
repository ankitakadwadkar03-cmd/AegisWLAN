import {
  IconDashboard,
  IconWifi,
  IconActivity,
  IconCpu,
  IconFileSearch,
  IconStar,
  IconShieldAlert,
  IconReports,
  IconSettings,
} from '../components/Icons'

export const navGroups = [
  {
    group: 'OVERVIEW',
    items: [
      { id: 'Admin Dashboard', label: 'Admin Dashboard', icon: IconDashboard },
    ],
  },
  {
    group: 'MONITOR',
    items: [
      { id: 'WiFi Scan', label: 'Wi-Fi Scan', icon: IconWifi },
      { id: 'Live Monitor', label: 'Live Monitor', icon: IconActivity },
    ],
  },
  {
    group: 'ANALYSE',
    items: [
      { id: 'ML Engine', label: 'ML Engine', icon: IconCpu },
      { id: 'PCAP Analysis', label: 'PCAP Analysis', icon: IconFileSearch },
      { id: 'Network Recommendations', label: 'Recommendations', icon: IconStar },
    ],
  },
  {
    group: 'REVIEW',
    items: [
      { id: 'Incidents', label: 'Incidents', icon: IconShieldAlert },
      { id: 'Reports', label: 'Reports', icon: IconReports },
    ],
  },
  {
    group: 'SETTINGS',
    items: [
      { id: 'Settings', label: 'Settings', icon: IconSettings },
    ],
  },
]
