<?php
style('files_antivirus', 'settings');
script('files_antivirus', 'settings');
?>
<div class="section section-antivirus">
	<form id="antivirus" action="#" method="post">
		<fieldset class="personalblock">
			<h2><?php p($l->t('Antivirus for Files'));?></h2>
			<table>
				<tr class="av_mode">
					<td><label for="av_mode"><?php p($l->t('Mode'));?></label></td>
					<td>
						<select id="av_mode" name="avMode"><?php print_unescaped(html_select_options([
							'executable' => $l->t('ClamAV Executable'),
							'daemon' => $l->t('ClamAV Daemon'),
							'socket' => $l->t('ClamAV Daemon (Socket)'),
							'kaspersky' => $l->t('Kaspersky Daemon'),
							'icap' => $l->t('ICAP server'),
						], $_['avMode'])) ?></select>
					</td>
					<td></td>
				</tr>
				<tr class="av_socket">
					<td><label for="av_socket"><?php p($l->t('Socket'));?></label></td>
					<td><input type="text" id="av_socket" name="avSocket" value="<?php p($_['avSocket']); ?>" title="<?php p($l->t('ClamAV Socket.')).' '.$l->t('Not required in Executable Mode.'); ?>"></td>
					<td></td>
				</tr>
				<tr class="av_host">
					<td><label for="av_host"><?php p($l->t('Host'));?></label></td>
					<td><input type="text" id="av_host" name="avHost" value="<?php p($_['avHost']); ?>" title="<?php p($l->t('Address of Antivirus Host.')). ' ' .$l->t('Not required in Executable Mode.');?>"></td>
					<td></td>
				</tr>
				<tr class="av_port">
					<td><label for="av_port"><?php p($l->t('Port'));?></label></td>
					<td><input type="text" id="av_port" name="avPort" value="<?php p($_['avPort']); ?>" title="<?php p($l->t('Port number of Antivirus Host.')). ' ' .$l->t('Not required in Executable Mode.');?>"></td>
					<td></td>
				</tr>
				<tr class="av_icap_preset">
					<td><?php p($l->t('ICAP preset'));?></td>
					<td><select id="av_icap_preset">
							<option value="none" selected="selected"><?php p($l->t('Select'));?></option>
							<option value="clamav">ClamAV / c-icap</option>
							<option value="kaspersky">Kaspersky</option>
						</select></td>
					<td></td>
				</tr>
				<tr class="av_icap_mode">
					<td><?php p($l->t('ICAP mode'));?></td>
					<td><select id="av_icap_mode" name="avIcapMode">
							<option value="reqmod">REQMOD</option>
							<option value="respmod">RESPMOD</option>
						</select></td>
					<td></td>
				</tr>
				<tr class="av_icap_service">
					<td><label for="av_icap_service"><?php p($l->t('ICAP service'));?></label></td>
					<td><input type="text" id="av_icap_service" name="avIcapRequestService" value="<?php p($_['avIcapRequestService']); ?>" /></td>
					<td></td>
				</tr>
				<tr class="av_icap_header">
					<td><label for="av_icap_header"><?php p($l->t('ICAP virus response header'));?></label></td>
					<td><input type="text" id="av_icap_header" name="avIcapResponseHeader" value="<?php p($_['avIcapResponseHeader']); ?>" /></td>
					<td></td>
				</tr>
				<tr class="av_stream_max_length">
					<td><label for="av_stream_max_length"><?php p($l->t('Stream Length'));?></label></td>
					<td>
					<input type="text" id="av_stream_max_length" name="avStreamMaxLength" value="<?php p($_['avStreamMaxLength']); ?>"
						   title="<?php p($l->t('ClamAV StreamMaxLength value in bytes.')). ' ' .$l->t('Not required in Executable Mode.');?>"
					/>
					</td>
					<td><label for="av_stream_max_length" class="a-left"><?php p($l->t('bytes'))?></label></td>
				</tr>
				<tr class="av_path">
					<td><label for="av_path"><?php p($l->t('Path to clamscan'));?></label></td>
					<td><input type="text" id="av_path" name="avPath" value="<?php p($_['avPath']); ?>" title="<?php p($l->t('Path to clamscan executable.')). ' ' .$l->t('Not required in Daemon Mode.');?>" /></td>
					<td></td>
				</tr>
				<tr class="av_path">
					<td><label for="av_cmd_options"><?php p($l->t('Extra command line options (comma-separated)'));?></label></td>
					<td><input type="text" id="av_cmd_options" name="avCmdOptions" value="<?php p($_['avCmdOptions']); ?>" /></td>
					<td></td>
				</tr>
				<tr class="av_max_file_size">
					<td><label for="av_max_file_size"><?php p($l->t('File size limit for periodic background scans and chunked uploads, -1 means no limit'));?></label></td>
					<td>
						<input type="text" id="av_max_file_size" name="avMaxFileSize" value="<?php p($_['avMaxFileSize']); ?>"
						   title="<?php p($l->t('Background scan and chunked upload file size limit in bytes, -1 means no limit'));?>"
						/>
					</td>
					<td><label for="av_max_file_size" class="a-left"><?php p($l->t('bytes'))?></label></td>
				</tr>
				<tr class="av_scan_first_bytes">
					<td><label for="av_scan_first_bytes"><?php p($l->t('Check only first bytes of the file, -1 means no limit'));?></label></td>
					<td>
						<input type="text" id="av_scan_first_bytes" name="avScanFirstBytes" value="<?php p($_['avScanFirstBytes']); ?>"
						   title="<?php p($l->t('Check only first bytes of the file, -1 means no limit'));?>"
						/>
					</td>
					<td><label for="av_scan_first_bytes" class="a-left"><?php p($l->t('bytes'))?></label></td>
				</tr>
				<tr class="infected_action">
					<td><label for="av_infected_action"><?php p($l->t('When infected files are found during a background scan'));?></label></td>
					<td><select id="av_infected_action" name="avInfectedAction"><?php print_unescaped(html_select_options(['only_log' => $l->t('Only log'), 'delete' => $l->t('Delete file')], $_['avInfectedAction'])) ?></select></td>
					<td></td>
				</tr>
			</table>
			<input id="av_submit" type="submit" value="<?php p($l->t('Save'));?>" />
			<span id="antivirus_save_msg"></span>
		</fieldset>
	</form>
	<div id="antivirus-advanced-wrapper">
		<hr />
		<button id="antivirus-advanced"><?php p($l->t('Advanced')) ?></button>
		<div class="spoiler">
			<h3><?php p($l->t('Rules')) ?></h3>
			<div id="antivirus-buttons">
				<button id="antivirus-clear"><?php p($l->t('Clear All')) ?></button>
				<button id="antivirus-reset"><?php p($l->t('Reset to defaults')) ?></button>
			</div>
			<table id="antivirus-statuses" class="grid">
				<thead>
				<tr>
					<th></th>
					<th><?php p($l->t('Match by')) ?></th>
					<th><?php p($l->t('Scanner exit status or signature to search')) ?></th>
					<th><?php p($l->t('Description')); ?></th>
					<th><?php p($l->t('Mark as')) ?></th>
					<th></th>
				</tr>
				</thead>
				<tbody>
				</tbody>
			</table>
			<button id="antivirus-add" class="icon-add"><?php p($l->t('Add a rule')) ?></button>
		</div>
	</div>
</div>
