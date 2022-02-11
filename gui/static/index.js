let files = [];
let breakpoints = [];
let watchpoints = [];
let registers = [];

let current_file = 0;
let current_position = {address: "", line: "", file: ""};
let last_position    = {address: "", line: "", file: ""};

function attach_frag_children(host_elem, frag_elem) {
	if (host_elem.firstChild) {
		let section_parent = host_elem.parentElement;
		let new_host_elem = host_elem.cloneNode();
		new_host_elem.appendChild(frag_elem);
		section_parent.replaceChild(new_host_elem, host_elem)
	} else {
		host_elem.appendChild(frag_elem);
	}
}

function generate_tagged_text(tag_type, text) {
	let tag_elem = document.createElement(tag_type);
	let text_elem = document.createTextNode(text);
	tag_elem.appendChild(text_elem);

	return tag_elem;
}

async function toggle_breakpoint(file_name, line_num) {
	let line_elem = document.getElementById('code-line-' + line_num);
	let toggle_val = line_elem.classList.toggle("line-break");

	if (toggle_val) {
		await fetch('/set_breakpoint?file=' + file_name + "&line=" + line_num);
	} else {
		await fetch('/clear_breakpoint?file=' + file_name + "&line=" + line_num);
	}

	await get_breakpoints();
}

async function get_file_list() {
	let response = await fetch('/get_file_list');
	let file_list = await response.json();
	files = file_list.paths;
	current_file = 0;

	for (let i = 0; i < files.length; i++) {
		files[i].data = await get_file(files[i]);
	}
}

async function get_file(path_blob) {
	let file_path = path_blob.path + "/" + path_blob.name;
	let response = await fetch('/get_file?file=' + file_path);
	let file_blob = await response.json();
	return file_blob;
}

async function single_step() {
	await fetch('/single_step');
	await get_registers();
	await get_current_position();
	await get_breakpoints();
	await get_watchpoints();

	render_page();
}

async function step_into() {
	await fetch('/step_into');
	await get_registers();
	await get_current_position();
	await get_breakpoints();
	await get_watchpoints();

	render_page();
}

async function run_line() {
	await fetch('/run_line');
	await get_registers();
	await get_current_position();
	await get_breakpoints();
	await get_watchpoints();

	render_page();
}

async function cont() {
	await fetch('/cont');
	await get_registers();
	await get_current_position();
	await get_breakpoints();
	await get_watchpoints();

	render_page();
}

async function restart() {
	await fetch('/restart');
	current_position = {address: "", line: "", file: ""};
	old_position = {address: "", line: "", file: ""};

	await get_registers();
	await get_current_position();
	await get_breakpoints();
	await get_watchpoints();

	render_page();
}

async function get_registers() {
	let response = await fetch('/get_registers');
	registers = await response.json();
}

async function get_current_position() {
	let response = await fetch('/current_position');
	let new_position = await response.json();

	old_position = current_position;
	current_position = new_position;
}

async function get_breakpoints() {
	let response = await fetch('/breakpoints');
	breakpoints = await response.json();	
}

async function get_watchpoints() {
	let response = await fetch('/watchpoints');
	watchpoints = await response.json();	
}

function render_registers() {
	let reg_display_elem = document.getElementById('register-display');
	let reg_frag = document.createDocumentFragment();

	reg_frag.appendChild(generate_tagged_text("h3", "Registers"));

	for (let i = 0; i < registers.length; i++) {
		let register = registers[i];

		let reg_line = document.createElement("div");
		reg_line.classList.add("register-line");
		
		reg_line.appendChild(generate_tagged_text("p", register.name + ":"));
		reg_line.appendChild(generate_tagged_text("span", register.value));
		reg_frag.appendChild(reg_line);	
	}

	attach_frag_children(reg_display_elem, reg_frag);
}

function render_file_list() {
	let ftree_display_elem = document.getElementById('ftree-display');

	let ftree_frag = document.createDocumentFragment();
	for (let i = 0; i < files.length; i++) {
		let file = files[i];
		let fline = generate_tagged_text("p", file.name);

		if (i == current_file) {
			fline.classList.add("current-file");
		} else {
			let cur_idx = i.valueOf();
			fline.addEventListener("click", () => { 
				current_file = cur_idx;
				render_page();
			});
		}

		ftree_frag.appendChild(fline);
	}

	attach_frag_children(ftree_display_elem, ftree_frag);	
}

function render_breakpoints() {
	for (let i = 0; i < breakpoints.length; i++) {
		let bp = breakpoints[i];
		if (bp.file == files[current_file].name) {
			let line_elem = document.getElementById('code-line-' + bp.line);
			line_elem.classList.add("line-break");
		}
	}
}

function render_position() {
	if (current_position.line == "") {
		return;
	}

	if (current_position.file == files[current_file].name) {
		let line_elem = document.getElementById('code-line-' + current_position.line);
		line_elem.classList.add("line-active");
	}

	if (current_position.line != "" && current_position.line != old_position.line && old_position.file == files[current_file].name) {
		let old_line_elem = document.getElementById('code-line-' + old_position.line);
		old_line_elem.classList.remove("line-active");
	}
}

function render_file(file) {
	let file_elem = document.getElementById('file-display');

	let chunk = file.data.data;
	let file_name = file.name;

	let re = /\n|\r|\r\n/gm;
	let start_idx = 0;
	let file_frag = document.createDocumentFragment();
	let line_count = 1;

	file_frag.appendChild(generate_tagged_text("h3", "File - " + file_name));

	let file_display_elem = document.createElement("div");
	for (;;) {
		let line_elem = document.createElement("div");
		line_elem.classList.add("code-line-wrapper");

		let pre_elem = document.createElement("pre");
		let code_elem = document.createElement("code");
		pre_elem.appendChild(code_elem);

		let ret = re.exec(chunk);
		if (!ret) {
			break;
		}

		let rem = chunk.substring(0, re.lastIndex);
		let line = chunk.substring(0, re.lastIndex);
		chunk = chunk.substring(re.lastIndex);
		re.lastIndex = 0;

		let count_elem = document.createElement("span");
		let cur_line_count = line_count.valueOf();
		count_elem.setAttribute('data-line-number', cur_line_count);
		count_elem.classList.add('code-line');
		count_elem.addEventListener("click", () => { toggle_breakpoint(file_name, cur_line_count); });

		line_elem.setAttribute('id', 'code-line-' + cur_line_count);
		line_elem.appendChild(count_elem);

		if (line[0] === undefined) {
			let break_elem = document.createElement("br");
			line_elem.appendChild(break_elem);
		} else {
			let file_text = document.createTextNode(line);
			code_elem.appendChild(file_text);
			line_elem.appendChild(pre_elem);
		}

		file_display_elem.appendChild(line_elem);
		start_idx = re.lastIndex;
		line_count += 1;
	}

	let line_count_width = Math.floor(Math.log10(line_count)) + 1;
	document.documentElement.style.setProperty('--line-count-width', line_count_width + 'ch');

	file_frag.appendChild(file_display_elem);
	attach_frag_children(file_elem, file_frag);
}

function render_watchpoints() {
	let watchpoint_elem = document.getElementById('watchpoint-display');
	let watch_frag = document.createDocumentFragment();

	watch_frag.appendChild(generate_tagged_text("h3", "Watchpoints"));
	let input_elem = document.createElement("input");
	input_elem.setAttribute('placeholder', 'enter watchpoint here...');
	input_elem.addEventListener("keyup", (ev) => {
		if (ev.keyCode == 13) {
			event.preventDefault();

			fetch('/set_watchpoint?var=' + ev.target.value)
			.then(get_watchpoints)
			.then(render_watchpoints);
		}
	});
	watch_frag.appendChild(input_elem);

	for (let i = 0; i < watchpoints.length; i++) {
		let wp = watchpoints[i];

		let watch_line = document.createElement("div");
		watch_line.classList.add("watch-line");

		watch_line.appendChild(generate_tagged_text("p", wp.variable + ":"));
		watch_line.appendChild(generate_tagged_text("span", wp.value));

		watch_frag.appendChild(watch_line);
	}

	attach_frag_children(watchpoint_elem, watch_frag);
}

function render_page() {
	render_registers();

	for (let i = 0; i < files.length; i++) {
		if (files[i].name == current_position.file) {
			current_file = i;
			break;
		}
	}

	render_file_list();
	render_file(files[current_file]);
	render_breakpoints();
	render_position();
	render_watchpoints();
}

async function main() {
	await get_file_list();
	await get_registers();
	await get_current_position();
	await get_breakpoints();
	await get_watchpoints();

	render_page();
}
