"""Create a reference-derived thesis DOCX with the bundled authoring runtime.

This author tool is not a product dependency. The retained reference stays read-only;
all unrelated OOXML parts are copied byte-for-byte. Native Word refresh/render is a
separate verification step. Run with Codex's bundled Python, lxml and Pillow.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from copy import deepcopy
from pathlib import Path
from zipfile import ZIP_DEFLATED, ZipFile

from lxml import etree
from PIL import Image, ImageDraw, ImageFont

W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
PR = "http://schemas.openxmlformats.org/package/2006/relationships"
NS = {"w": W, "r": R}
CN = ["零", "一", "二", "三", "四", "五", "六", "七", "八", "九", "十"]
REFERENCE_SHA = "15398874c41e445b4df6bd4468984f77a646f56175191f2c6b14c7d3994658dc"


def node(tag: str, **attrs: str) -> etree._Element:
    element = etree.Element(f"{{{W}}}{tag}")
    for key, value in attrs.items():
        element.set(f"{{{W}}}{key}", value)
    return element


def xml(element: etree._Element) -> bytes:
    return etree.tostring(
        element, encoding="UTF-8", xml_declaration=True, standalone=True
    )


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def text_of(element: etree._Element) -> str:
    return "".join(element.xpath(".//w:t/text()", namespaces=NS))


def make_figures(directory: Path, font_path: Path) -> list[Path]:
    font = ImageFont.truetype(str(font_path), 34)
    small = ImageFont.truetype(str(font_path), 28)

    def canvas(height: int):
        picture = Image.new("RGB", (1600, height), "white")
        return picture, ImageDraw.Draw(picture)

    def box(draw, coords, lines):
        draw.rectangle(coords, outline="black", width=3)
        x0, y0, x1, y1 = coords
        for index, line in enumerate(lines):
            draw.text(
                ((x0 + x1) / 2, (y0 + y1) / 2 + (index - (len(lines) - 1) / 2) * 48),
                line,
                fill="black",
                font=font,
                anchor="mm",
            )

    def arrow(draw, coords):
        draw.line(coords, fill="black", width=3)
        x0, y0, x1, y1 = coords[-4:]
        if x1 != x0:
            draw.line((x1 - 12, y1 - 9, x1, y1, x1 - 12, y1 + 9), fill="black", width=3)
        else:
            sign = 1 if y1 > y0 else -1
            draw.line(
                (x1 - 9, y1 - 12 * sign, x1, y1, x1 + 9, y1 - 12 * sign),
                fill="black",
                width=3,
            )

    picture, draw = canvas(600)
    box(draw, (20, 190, 240, 315), ["浏览器", "导入与报告"])
    box(draw, (295, 190, 535, 315), ["回环 HTTP", "来源与令牌校验"])
    box(draw, (590, 190, 850, 315), ["快照与任务服务", "调度与保存"])
    box(draw, (955, 40, 1215, 155), ["静态扫描进程"])
    box(draw, (1305, 40, 1580, 155), ["AST 与", "Tree-sitter"])
    box(draw, (955, 360, 1215, 475), ["AI 复核进程", "明确同意后"])
    box(draw, (1305, 360, 1580, 475), ["模型路由", "本机 Ollama"])
    box(draw, (590, 400, 850, 530), ["SQLite", "静态与 AI 分表"])
    arrow(draw, [240, 252, 295, 252])
    arrow(draw, [535, 252, 590, 252])
    arrow(draw, [850, 252, 900, 252, 900, 97, 955, 97])
    arrow(draw, [850, 252, 900, 252, 900, 417, 955, 417])
    arrow(draw, [1215, 97, 1305, 97])
    arrow(draw, [1215, 417, 1305, 417])
    arrow(draw, [720, 315, 720, 400])
    draw.text(
        (800, 575),
        "工作进程用于控制超时  上传源码只解析不执行",
        font=small,
        fill="black",
        anchor="mm",
    )
    architecture = directory / "architecture.png"
    picture.save(architecture)
    picture, draw = canvas(310)
    labels = [
        ("projects", "项目快照"),
        ("tasks", "扫描任务"),
        ("findings", "静态证据"),
        ("ai_results", "AI 推断"),
    ]
    for index, lines in enumerate(labels):
        x = 20 + index * 410
        box(draw, (x, 85, x + 320, 220), lines)
        if index < 3:
            arrow(draw, [x + 320, 150, x + 410, 150])
            draw.text(
                (x + 365, 45),
                "1:N" if index < 2 else "1:0..1",
                font=small,
                fill="black",
                anchor="mm",
            )
    draw.text(
        (800, 280),
        "AI 结果通过 task_id 与 ordinal 关联静态发现",
        font=small,
        fill="black",
        anchor="mm",
    )
    database = directory / "database.png"
    picture.save(database)
    return [architecture, database]


def build(
    reference: Path, source: Path, output: Path, assets: Path, font: Path
) -> None:
    if output.exists():
        raise FileExistsError(output)
    if sha(reference.read_bytes()) != REFERENCE_SHA:
        raise ValueError("Reference differs from the distilled contract")
    assets.mkdir(parents=True, exist_ok=True)
    figures = make_figures(assets, font)
    figures.append(source.parent.parent / "tests/screenshots/graduation-ai-detail.jpg")
    with ZipFile(reference) as archive:
        parts = {name: archive.read(name) for name in archive.namelist()}
    document = etree.fromstring(parts["word/document.xml"])
    body = document.find("w:body", NS)
    originals = document.xpath("//w:body//w:p", namespaces=NS)
    children = list(body)

    def paragraph(index: int, text: str, *, largest_run: bool = False):
        original = originals[index]
        result = etree.Element(f"{{{W}}}p")
        properties = original.find("w:pPr", NS)
        if properties is not None:
            result.append(deepcopy(properties))
        runs = original.findall("w:r", NS)
        chosen = next(
            (run for run in runs if run.find("w:rPr", NS) is not None),
            runs[0] if runs else None,
        )
        if largest_run and runs:
            chosen = max(
                runs,
                key=lambda r: (
                    int(r.find("w:rPr/w:sz", NS).get(f"{{{W}}}val", "0"))
                    if r.find("w:rPr/w:sz", NS) is not None
                    else 0
                ),
            )
        props = chosen.find("w:rPr", NS) if chosen is not None else None
        for n, line in enumerate(text.split("\n")):
            run = node("r")
            if props is not None:
                run.append(deepcopy(props))
            if n:
                run.append(node("br"))
            content = node("t")
            content.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            content.text = line
            run.append(content)
            result.append(run)
        return result

    def prop(p, tag, **attrs):
        ppr = p.find("w:pPr", NS)
        if ppr is None:
            ppr = node("pPr")
            p.insert(0, ppr)
        old = ppr.find(f"w:{tag}", NS)
        if old is not None:
            ppr.remove(old)
        ppr.append(node(tag, **attrs))

    def field(p, instruction, value, begin=False, end=False):
        if begin:
            run = node("r")
            run.append(node("fldChar", fldCharType="begin"))
            p.append(run)
            run = node("r")
            instr = node("instrText")
            instr.text = instruction
            instr.set("{http://www.w3.org/XML/1998/namespace}space", "preserve")
            run.append(instr)
            p.append(run)
            run = node("r")
            run.append(node("fldChar", fldCharType="separate"))
            p.append(run)
        if value is not None:
            run = node("r")
            content = node("t")
            content.text = value
            run.append(content)
            p.append(run)
        if end:
            run = node("r")
            run.append(node("fldChar", fldCharType="end"))
            p.append(run)

    raw = source.read_text(encoding="utf-8")
    title = raw.splitlines()[0].removeprefix("# ")
    raw = raw.replace(
        "Python 全量回归及新功能测试的最终计数以随交付测试报告为准，子集不重复相加。",
        "Python 集成回归实际为 427 passed，另有一项既有 pytest cache_dir 警告；子集不重复相加。",
    )
    raw = raw.replace(
        "安装版两个实际任务约 0.676 秒和 0.689 秒，网页演示任务 1.123 秒。",
        "最终交付安装版的 AI 成功路径在重启前后两次静态任务分别约为 0.655 秒和 0.656 秒；网页演示任务为 1.123 秒。",
    )
    raw = raw.replace("### 6.4 误报 漏报与耗时", "### 6.4 误报与漏报及耗时")
    raw = raw.replace(
        "学校模板、个人信息和独立学术\n验收需要在正式提交前补齐。",
        "个人信息、学校格式审核和独立学术\n验收需要在正式提交前完成。",
    )
    raw = raw.replace(
        "本节由学生补充实际得到的指导和帮助，通用初稿不虚构导师、学校或他人贡献。",
        "本系统的实现与验证使用了 Python、Tree-sitter、SQLite 等开源项目及公开技术文档。感谢相关项目维护者提供的工具与资料。",
    )
    (assets / "adapted-source.md").write_text(raw, encoding="utf-8")
    abstract = raw.split("## 摘要\n\n", 1)[1].split("## Abstract", 1)[0]
    abstract_text, keywords = abstract.strip().split("\n\n关键词：", 1)
    content = raw.split("## 第一章", 1)[1]
    content = "## 第一章" + content
    blocks = []
    pending = []
    fenced = False
    for line in content.strip().splitlines():
        if line.startswith("```"):
            fenced = not fenced
        if not line.strip() and not fenced:
            if pending:
                blocks.append("\n".join(pending))
                pending = []
        else:
            pending.append(line)
    if pending:
        blocks.append("\n".join(pending))
    headings = []
    sections = []
    chapter = 0
    for block in blocks:
        if block.startswith("## "):
            text = block[3:].strip()
            match = re.match(r"第([一二三四五六七])章\s+(.+)", text)
            if match:
                chapter += 1
                text = f"{CN[chapter]}、{match.group(2)}"
            sections.append(("heading", text, 1))
            headings.append((text, 1))
        elif block.startswith("### "):
            match = re.match(r"### \d+\.(\d+)\s+(.+)", block)
            text = f"（{CN[int(match.group(1))]}）{match.group(2)}"
            sections.append(("heading", text, 2))
            headings.append((text, 2))
        elif block.startswith("```mermaid"):
            sections.append(("image", 0 if "flowchart" in block else 1, 0))
        elif block.startswith("!["):
            sections.append(("image", 2, 0))
        elif block.startswith("```"):
            sections.append(("code", block.split("\n", 1)[1].rsplit("\n```", 1)[0], 0))
        elif block.startswith("|"):
            rows = [
                [cell.strip() for cell in line.strip().strip("|").split("|")]
                for line in block.splitlines()
                if line.startswith("|")
            ]
            sections.append(("table", [rows[0]] + rows[2:], 0))
        else:
            text = re.sub(r"(?<=\S)\n(?=\S)", "", block.strip())
            sections.append(("body", text, 0))

    # Preserve cover/form in place, replacing only authorized text slots.
    for index, text in {
        0: " ",
        3: "题目：基于 Python 与大语言模型的\n源代码安全检测系统设计与实现",
        7: "分部：",
        8: "学习中心：",
        9: "专业：",
        10: "入学时间：",
        11: "学号：",
        12: "姓名：",
        13: "指导教师：",
        18: "               论文完成日期：      年    月",
        22: "毕  业  设  计（论文）",
        27: f"       本人慎重承诺和声明：本论文《{title}》的实现、数据及引用来源将在提交前由本人核验，辅助工具的使用情况将如实说明。本人愿为经本人确认后正式提交的内容承担责任。",
        28: "设计（论文）的成果归属按学校相关规定办理。",
        35: "                                     学生（签名）：",
        36: "                         年    月    日",
    }.items():
        target = originals[index]
        new = paragraph(index, text, largest_run=index == 27)
        target.getparent().replace(target, new)
    # Source institutional abbreviation is removed; no assertions of past guidance.

    result = list(body)[:25]  # cover, commitment table, TOC heading and spacer
    toc_rows = []
    for index, (text, level) in enumerate(headings):
        p = paragraph(41 if level == 1 else 43, "")
        for child in list(p):
            if child.tag != f"{{{W}}}pPr":
                p.remove(child)
        if index == 0:
            field(p, ' TOC \\o "1-2" \\h \\z \\u ', None, begin=True)
        link = etree.Element(f"{{{W}}}hyperlink")
        link.set(f"{{{W}}}anchor", f"_Thesis{index:03}")
        run = deepcopy(paragraph(41 if level == 1 else 43, text).find("w:r", NS))
        link.append(run)
        tab = node("r")
        tab.append(node("tab"))
        link.append(tab)
        field(link, f" PAGEREF _Thesis{index:03} \\h ", "0", begin=True, end=True)
        p.append(link)
        if index == len(headings) - 1:
            field(p, "", None, end=True)
        toc_rows.append(p)
    result.extend(toc_rows)
    result.append(deepcopy(originals[52]))
    result.extend(
        [
            deepcopy(originals[53]),
            deepcopy(originals[54]),
            paragraph(55, abstract_text.replace("\n", "")),
            deepcopy(originals[56]),
        ]
    )
    keyword_p = paragraph(57, "关键词：")
    keyword_run = deepcopy(paragraph(55, keywords.strip()).find("w:r", NS))
    keyword_p.append(keyword_run)
    result.append(keyword_p)
    result.append(deepcopy(originals[58]))

    # Add image relationships without touching any existing relationship entry.
    relationships = etree.fromstring(parts["word/_rels/document.xml.rels"])
    image_nodes = []
    from docx import Document
    from docx.shared import Inches

    # Use python-docx only as an inline drawing component factory, not as a saver.
    factory = Document(reference)
    for index, path in enumerate(figures):
        p = factory.add_paragraph()
        picture = p.add_run().add_picture(
            str(path), width=Inches(6.05 if index < 2 else 5.2)
        )
        picture._inline.docPr.set("id", str(100 + index))
        picture._inline.docPr.set(
            "name", ["系统架构", "数据库关系", "实际模型复核详情"][index]
        )
        picture._inline.docPr.set(
            "descr",
            [
                "服务编排静态和AI进程并分别保存结果",
                "项目任务发现与AI结果的关联",
                "实际本机模型复核区域截图",
            ][index],
        )
        drawing = etree.fromstring(etree.tostring(p._p))
        for blip in drawing.xpath(".//*[@r:embed]", namespaces=NS):
            blip.set(f"{{{R}}}embed", f"rIdThesis{index}")
        filename = f"thesis-{index}{path.suffix}"
        etree.SubElement(
            relationships,
            f"{{{PR}}}Relationship",
            Id=f"rIdThesis{index}",
            Type=R + "/image",
            Target="media/" + filename,
        )
        parts["word/media/" + filename] = path.read_bytes()
        prop(drawing, "jc", val="center")
        prop(drawing, "keepNext")
        prop(drawing, "keepLines")
        image_nodes.append(drawing)

    table_number = 0
    heading_number = 0
    in_references = False
    for kind, value, level in sections:
        if kind == "heading":
            if value == "参考文献":
                result.append(deepcopy(originals[99]))
                in_references = True
            pattern = 59 if level == 1 else 64
            p = paragraph(100 if value in {"参考文献", "致谢"} else pattern, value)
            if value.startswith("附录") or value == "致谢":
                prop(p, "pageBreakBefore")
            start = node(
                "bookmarkStart",
                id=str(400 + heading_number),
                name=f"_Thesis{heading_number:03}",
            )
            p.insert(1, start)
            p.append(node("bookmarkEnd", id=str(400 + heading_number)))
            heading_number += 1
            result.append(p)
        elif kind == "image":
            result.append(image_nodes[value])
        elif kind == "table":
            table_number += 1
            captions = [
                "表 3-1 需求与实现功能",
                "表 4-1 数据库字段与关联",
                "表 5-1 风险检测规则",
                "表 6-1 静态与 AI 对照实验",
            ]
            cap = paragraph(60, captions[table_number - 1])
            prop(cap, "jc", val="center")
            prop(cap, "ind", firstLine="0")
            prop(cap, "keepNext")
            result.append(cap)
            table = node("tbl")
            pr = node("tblPr")
            pr.extend(
                [node("tblW", w="9175", type="dxa"), node("tblLayout", type="fixed")]
            )
            table.append(pr)
            borders = node("tblBorders")
            for edge in ("top", "left", "bottom", "right", "insideH", "insideV"):
                borders.append(node(edge, val="single", sz="4", color="D9D9D9"))
            pr.append(borders)
            margins = node("tblCellMar")
            for side in ("top", "bottom", "left", "right"):
                margins.append(node(side, w="90", type="dxa"))
            pr.append(margins)
            widths = [
                [1850, 3700, 3625],
                [1300, 1600, 4400, 1875],
                [1900, 3200, 4075],
                [3150, 650, 650, 650, 650, 1712, 1713],
            ][table_number - 1]
            grid = node("tblGrid")
            for width in widths:
                grid.append(node("gridCol", w=str(width)))
            table.append(grid)
            for row_index, row in enumerate(value):
                tr = node("tr")
                trpr = node("trPr")
                trpr.append(node("cantSplit"))
                if row_index == 0:
                    trpr.append(node("tblHeader"))
                tr.append(trpr)
                for col_index, cell_text in enumerate(row):
                    cell = node("tc")
                    cellpr = node("tcPr")
                    cellpr.extend(
                        [
                            node("tcW", w=str(widths[col_index]), type="dxa"),
                            node("vAlign", val="center"),
                        ]
                    )
                    cell.append(cellpr)
                    p = paragraph(60, cell_text)
                    prop(p, "ind", firstLine="0", firstLineChars="0")
                    prop(p, "jc", val="left")
                    prop(p, "spacing", line="300", lineRule="auto")
                    if row_index == 0:
                        for rpr in p.findall("w:r/w:rPr", NS):
                            rpr.append(node("b"))
                    cell.append(p)
                    tr.append(cell)
                table.append(tr)
            result.append(table)
        elif kind == "code":
            p = paragraph(60, value)
            prop(p, "ind", firstLine="0", firstLineChars="0")
            prop(p, "jc", val="left")
            prop(p, "keepLines")
            for rpr in p.findall("w:r/w:rPr", NS):
                rpr.append(
                    node("rFonts", ascii="Consolas", hAnsi="Consolas", eastAsia="宋体")
                )
            result.append(p)
        else:
            p = paragraph(101 if in_references and value.startswith("[") else 60, value)
            prop(p, "widowControl")
            if value.startswith("图 "):
                prop(p, "jc", val="center")
                prop(p, "ind", firstLine="0", firstLineChars="0")
            result.append(p)
    result.append(deepcopy(children[-1]))
    for child in list(body):
        body.remove(child)
    body.extend(result)
    for mark in document.xpath("//w:bookmarkStart|//w:bookmarkEnd", namespaces=NS):
        is_new = (
            mark.get(f"{{{W}}}name", "").startswith("_Thesis")
            if mark.tag == f"{{{W}}}bookmarkStart"
            else 400 <= int(mark.get(f"{{{W}}}id", "-1")) < 400 + len(headings)
        )
        if not is_new:
            mark.getparent().remove(mark)
    parts["word/document.xml"] = xml(document)
    parts["word/_rels/document.xml.rels"] = xml(relationships)
    types = etree.fromstring(parts["[Content_Types].xml"])
    ctns = "http://schemas.openxmlformats.org/package/2006/content-types"
    for extension, content_type in [("png", "image/png"), ("jpg", "image/jpeg")]:
        if not any(x.get("Extension") == extension for x in types):
            etree.SubElement(
                types,
                f"{{{ctns}}}Default",
                Extension=extension,
                ContentType=content_type,
            )
    parts["[Content_Types].xml"] = xml(types)
    core = etree.fromstring(parts["docProps/core.xml"])
    for element in core:
        local = etree.QName(element).localname
        if local in {"creator", "lastModifiedBy", "subject", "keywords", "description"}:
            element.text = ""
        elif local == "title":
            element.text = title
    parts["docProps/core.xml"] = xml(core)
    output.parent.mkdir(parents=True, exist_ok=True)
    with ZipFile(output, "w", ZIP_DEFLATED) as z:
        for name, data in parts.items():
            z.writestr(name, data)
    receipt = {
        "source_sha256": sha(source.read_bytes()),
        "reference_sha256": REFERENCE_SHA,
        "candidate_sha256": sha(output.read_bytes()),
        "headings": headings,
        "tables": table_number,
        "images": 3,
    }
    (assets / "build-receipt.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(
        json.dumps(
            {
                "output": str(output),
                "headings": len(headings),
                "tables": table_number,
                "images": 3,
            },
            ensure_ascii=False,
        )
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--reference", type=Path, required=True)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--assets", type=Path, required=True)
    parser.add_argument(
        "--font", type=Path, default=Path("C:/Windows/Fonts/simsun.ttc")
    )
    args = parser.parse_args()
    build(args.reference, args.source, args.output, args.assets, args.font)
