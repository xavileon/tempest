./run_tempest.sh -t tempest.api.network \
    tempest.scenario.test_network_basic_ops \
    tempest.scenario.test_network_advanced_server_ops \
    tempest.scenario.test_security_groups_basic_ops \
    tempest.scenario.midokura 2>&1 | tee test_results_complete_$(date +%y%d%M-%H%m).log
