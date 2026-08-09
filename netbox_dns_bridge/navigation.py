from netbox.plugins import PluginMenu, PluginMenuButton, PluginMenuItem

_static_target_buttons = [
    PluginMenuButton(
        link="plugins:netbox_dns_bridge:staticnotifytarget_add",
        title="Add",
        icon_class="mdi mdi-plus-thick",
    ),
]

menu = PluginMenu(
    label="DNS Bridge",
    icon_class="mdi mdi-dns",
    groups=(
        (
            "NOTIFY",
            (
                PluginMenuItem(
                    link="plugins:netbox_dns_bridge:staticnotifytarget_list",
                    link_text="Static NOTIFY Targets",
                    buttons=_static_target_buttons,
                ),
                PluginMenuItem(
                    # Read-only registry of dynamic NOTIFY targets.
                    link="plugins:netbox_dns_bridge:seentransferclient_list",
                    link_text="Seen Transfer Clients",
                ),
                PluginMenuItem(
                    # pk-less landing (notifyconfig itself is now pk-based);
                    # redirects to the singleton detail.
                    link="plugins:netbox_dns_bridge:notifyconfig_list",
                    link_text="NOTIFY Configuration",
                ),
            ),
        ),
    ),
)
