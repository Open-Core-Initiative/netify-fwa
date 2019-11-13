<?php
require_once('guiconfig.inc');
require_once('/usr/local/pkg/netify-fwa/netify-fwa.inc');

if ($_POST['status'] == 'update') {
	$status = array(
		'version' => NETIFY_FWA_VERSION,
		'running' => netify_fwa_is_running(),
		'status' => array()
	);

	if (file_exists(NETIFY_FWA_JSON_STATUS)) {
		$status['status'] = json_decode(
			file_get_contents(NETIFY_FWA_JSON_STATUS)
		);
	}
	else {
		$status['error'] = 'FWA status file not found.';
	}

	$response = json_encode($status);
	header('Content-Type: application/json');
	header('Content-Length: ' . strlen($response));

	echo json_encode($status);

	exit;
}

include("head.inc");
$pgtitle = array(gettext('Services'), gettext('Netify FWA'), gettext('Status'));

$tab_array = array();
$tab_array[] = array(gettext("Status"), true, "/netify-fwa/netify-fwa_status.php");

display_top_tabs($tab_array, true);

?>

<div class="panel panel-default">
	<div class="panel-heading">
		<h2 class="panel-title"><?=gettext("Netify FWA Status")?></h2>
	</div>
	<div class="panel-body">
		<div class="content table-responsive">
			<table id="maintable" class="table table-striped table-hover table-condensed">
				<tr>
					<th>Version</th>
					<td id="fwa_version"></td>
					<th>Status</th>
					<td id="fwa_status">Unknown</td>
				</tr>
			</table>
		</div>
	</div>
</div>

<script type="text/javascript">
//<![CDATA[

	function statusRequest() {

		$.ajax(
			"<?=$_SERVER['SCRIPT_NAME'];?>",
			{
				type: 'post',
				data: {
					status: 'update'
				},
				success: statusUpdate,
				complete: function() {
					setTimeout(statusRequest, 2000);
				}
			}
		);
	}

	function statusUpdate(responseData) {
		/*
		{
		  "type": "agent_status",
		  "timestamp": 1573494902,
		  "uptime": 540,
		  "flows": 55,
		  "flows_prev": 35,
		  "maxrss_kb": 42308,
		  "maxrss_kb_prev": 42300,
		  "dhc_status": true,
		  "dhc_size": 16,
		  "sink_status": true,
		  "sink_queue_size_kb": 0,
		  "sink_queue_max_size_kb": 2048,
		  "sink_resp_code": 1
		}
		*/
		console.log('statusUpdate:');

		for(var key in responseData.status) {
			console.log(
				'key: ' + key +
				', value: ' + responseData.status[key]
			);
		}
/*
		$('#agent_version').html('v' + responseData.version);
		$('#agent_status').html(responseData.running ? 'Running' : 'Stopped');
		$('#agent_status').addClass(
			responseData.running ? 'text-success' : 'text-danger'
		);
		$('#agent_status').removeClass(
			responseData.running ? 'text-danger' : 'text-success'
		);
		var timestamp = new Date(responseData.status['timestamp'] * 1000);
		$('#agent_timestamp').html(timestamp.toLocaleString());
		$('#agent_uptime').html(uptime(responseData.status['uptime']));
		$('#agent_sink_status').html(responseData.status['sink_status']);
		$('#agent_sink_resp_code').html(responseData.status['sink_resp_code']);
		var sink_queue_percentage =
			responseData.status['sink_queue_size_kb'] * 100 /
			responseData.status['sink_queue_max_size_kb'];
		var sink_queue_percentage_options = {
			'style': 'percent',
			'minimumFractionDigits': 2,
			'maximumFractionDigits': 2
		};
		$('#agent_sink_queue_size').html(
			responseData.status['sink_queue_size_kb'].toLocaleString() + ' kB (' +
			sink_queue_percentage.toLocaleString('en-US',
				sink_queue_percentage_options) + ')'
		);
		$('#agent_sink_queue_size').addClass(
			sink_queue_percentage < 50 ? 'text-success' : 'text-danger'
		);
		$('#agent_sink_queue_size').removeClass(
			sink_queue_percentage >= 50 ? 'text-success' : 'text-danger'
		);
		$('#agent_sink_queue_max_size').html(
			responseData.status['sink_queue_max_size_kb'].toLocaleString() + ' kB'
		);
		$('#agent_flows').html(responseData.status['flows'].toLocaleString());
		$('#agent_flows_delta').html(
			(responseData.status['flows'] - 
			responseData.status['flows_prev']).toLocaleString()
		);
		$('#agent_maxrss').html(
			responseData.status['maxrss_kb'].toLocaleString() + ' kB'
		);
		$('#agent_maxrss_delta').html(
			(responseData.status['maxrss_kb'] - 
			responseData.status['maxrss_kb_prev']).toLocaleString() +
			' kB'
		);
		$('#agent_dhc_status').html(responseData.status['dhc_status']);
		$('#agent_dhc_size').html(
			responseData.status['dhc_size'].toLocaleString()
		);
*/
	}

	setTimeout(statusRequest, 1000);
//]]>
</script>

<?php
include("foot.inc");
?>
