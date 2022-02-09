function toggle_breakpoint(file_name, line_num) {
	let line_elem = document.getElementById('code-line-' + line_num);
	let toggle_val = line_elem.classList.toggle("line-break");

	if (toggle_val) {
		console.log("Added breakpoint in file " + file_name + " on line " + line_num);
	} else {
		console.log("Removed breakpoint in file " + file_name + " on line " + line_num);
	}
}

async function get_file() {
	let file_elem = document.getElementById('file-display');


	let response = await fetch('/get_file');
	let file_blob = await response.json();

	let chunk = file_blob.data;
	let file_name = file_blob.name;

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
	await get_file();
}
