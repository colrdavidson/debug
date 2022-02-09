async function toggle_breakpoint(file_name, line_num) {
	let line_elem = document.getElementById('code-line-' + line_num);
	let toggle_val = line_elem.classList.toggle("line-break");

	if (toggle_val) {
		await fetch('/set_breakpoint?file=' + file_name + "&line=" + line_num);
	} else {
		await fetch('/clear_breakpoint?file=' + file_name + "&line=" + line_num);
	}
}

async function get_file_list() {
	let response = await fetch('/get_file_list');
	return await response.json();
}

async function step_program() {
	await fetch('/step_program');
	await get_registers();
}

async function continue_program() {
	await fetch('/continue_program');
	await get_registers();
}

async function get_registers() {
	let response = await fetch('/get_registers');
	let registers = await response.json();

	let reg_display_elem = document.getElementById('register-display');
	while (reg_display_elem.firstChild) {
		reg_display_elem.removeChild(reg_display_elem.firstChild);
	}

	let reg_frag = document.createDocumentFragment();

	let reg_header_elem = document.createElement("h3");
	let reg_header_text = document.createTextNode("Registers");
	reg_header_elem.appendChild(reg_header_text);
	reg_frag.appendChild(reg_header_elem);

	for (let i = 0; i < registers.length; i++) {
		let register = registers[i];

		let reg_line = document.createElement("div");
		reg_line.classList.add("register-line");
		
		let reg_name = document.createTextNode(register.name + ":");
		let reg_name_elem = document.createElement("p");
		reg_name_elem.appendChild(reg_name);

		let reg_val = document.createTextNode(register.value);
		let reg_value_elem = document.createElement("span");
		reg_value_elem.appendChild(reg_val);

		reg_line.appendChild(reg_name_elem);
		reg_line.appendChild(reg_value_elem);

		reg_frag.appendChild(reg_line);	
	}

	reg_display_elem.appendChild(reg_frag);
}

async function get_file(path_blob) {
	let file_path = path_blob.path + "/" + path_blob.name;
	let response = await fetch('/get_file?file=' + file_path);
	let file_blob = await response.json();

	let file_elem = document.getElementById('file-display');
	while (file_elem.firstChild) {
		file_elem.removeChild(file_elem.firstChild);
	}

	let chunk = file_blob.data;
	let file_name = path_blob.name;

	let re = /\n|\r|\r\n/gm;
	let start_idx = 0;
	let file_frag = document.createDocumentFragment();
	let line_count = 1;

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

		file_frag.appendChild(line_elem);
		start_idx = re.lastIndex;
		line_count += 1;
	}

	let line_count_width = Math.floor(Math.log10(line_count)) + 1;

	let file_display_elem = document.createElement("div");
	file_display_elem.appendChild(file_frag);

	let file_header_elem = document.createElement("h3");
	let header_text = document.createTextNode("File - " + file_name);
	file_header_elem.appendChild(header_text);

	file_elem.appendChild(file_header_elem);
	file_elem.appendChild(file_display_elem);
	document.documentElement.style.setProperty('--line-count-width', line_count_width + 'ch');
}

async function main() {
	let file_list = await get_file_list();
	await get_file(file_list.paths[0]);
	await get_registers();
}
