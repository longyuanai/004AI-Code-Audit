"""Build a generic thesis PDF from reviewed Markdown using artifact dependencies.

Run with the Codex bundled Python (reportlab and Pillow), not a production install.
"""

from __future__ import annotations

import argparse
import re
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    Flowable,
    Image,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


class Diagram(Flowable):
    """A compact figure of the implemented architecture or database relation."""

    def __init__(self, database: bool = False) -> None:
        super().__init__()
        self.width, self.height = 480, 150
        self.database = database

    def draw(self) -> None:
        canvas = self.canv
        canvas.setFont("CJK", 10)
        canvas.setStrokeColor(colors.HexColor("#547080"))
        canvas.setFillColor(colors.black)
        if self.database:
            labels = ["projects", "tasks", "findings", "ai_results"]
            for index, label in enumerate(labels):
                x = index * 120
                canvas.roundRect(x, 65, 102, 42, 4)
                canvas.drawCentredString(x + 51, 82, label)
                if index < 3:
                    canvas.line(x + 102, 85, x + 120, 85)
            canvas.drawCentredString(240, 30, "项目 1:N 任务 1:N 发现 1:0..1 AI 结果")
            return
        rows = [
            ["浏览器", "回环 HTTP 校验", "快照与任务服务"],
            ["SQLite 静态与 AI 分表", "扫描或 AI 工作进程", "AST 扫描或模型路由"],
        ]
        for row, labels in enumerate(rows):
            for column, label in enumerate(labels):
                x, y = column * 163, 113 - row * 65
                canvas.roundRect(x, y, 145, 32, 3)
                canvas.drawCentredString(x + 72.5, y + 12, label)
                if column < 2 and (row == 0 or column == 1):
                    canvas.line(x + 145, y + 16, x + 163, y + 16)
        # The service dispatches the worker and persists results in SQLite.
        canvas.lines(
            [
                (398, 113, 398, 96),
                (398, 96, 235, 96),
                (235, 96, 235, 80),
                (365, 113, 365, 104),
                (365, 104, 72, 104),
                (72, 104, 72, 80),
            ]
        )
        canvas.drawCentredString(240, 0, "静态与 AI 分开保存  用户明确同意后才调用模型")


def text(raw: str) -> str:
    raw = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", raw)
    return escape(raw.replace("**", "").replace("`", ""))


def build(source: Path, output: Path, font: Path) -> None:
    if output.exists():
        raise FileExistsError(output)
    pdfmetrics.registerFont(TTFont("CJK", str(font)))
    body = ParagraphStyle(
        "body", fontName="CJK", fontSize=11, leading=20, spaceAfter=8, wordWrap="CJK"
    )
    h1 = ParagraphStyle(
        "chapter",
        parent=body,
        fontSize=18,
        leading=27,
        spaceAfter=16,
        keepWithNext=True,
    )
    h2 = ParagraphStyle(
        "section",
        parent=body,
        fontSize=13,
        leading=22,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True,
    )
    cell = ParagraphStyle("cell", parent=body, fontSize=9, leading=15, spaceAfter=0)
    code = ParagraphStyle("code", parent=body, fontSize=9, leading=15)
    title = ParagraphStyle(
        "title", parent=h1, fontSize=23, leading=36, alignment=TA_CENTER
    )
    content = source.read_text(encoding="utf-8").splitlines()
    story = [
        Spacer(1, 90),
        Paragraph(text(content[0][2:]), title),
        Spacer(1, 28),
        Paragraph("计算机应用技术专业毕业设计论文通用初稿", body),
        Paragraph("2026 年 10 月 9 日", body),
        Paragraph("待按学校模板调整并补充学生及指导教师信息", body),
        PageBreak(),
    ]
    index = next(i for i, line in enumerate(content) if line.startswith("## "))
    while index < len(content):
        line = content[index].strip()
        if not line:
            index += 1
            continue
        if line.startswith("## "):
            if len(story) > 8:
                story.append(PageBreak())
            story.append(Paragraph(text(line[3:]), h1))
        elif line.startswith("### "):
            story.append(Paragraph(text(line[4:]), h2))
        elif line.startswith("```"):
            kind = line[3:]
            block = []
            index += 1
            while index < len(content) and not content[index].startswith("```"):
                block.append(content[index])
                index += 1
            if kind == "mermaid":
                story.append(Diagram(database=any("erDiagram" in b for b in block)))
            else:
                story.append(Preformatted("\n".join(block), code))
        elif line.startswith("|"):
            rows = []
            while index < len(content) and content[index].startswith("|"):
                fields = [
                    field.strip()
                    for field in content[index].strip().strip("|").split("|")
                ]
                if not all(re.fullmatch(r"[-:]+", field) for field in fields):
                    rows.append([Paragraph(text(field), cell) for field in fields])
                index += 1
            index -= 1
            table = Table(
                rows,
                colWidths=[480 / len(rows[0])] * len(rows[0]),
                repeatRows=1,
                hAlign="LEFT",
            )
            table.setStyle(
                TableStyle(
                    [
                        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d9d9d9")),
                        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#e5edf1")),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 7),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 7),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            story.extend([table, Spacer(1, 12)])
        elif line.startswith("!["):
            match = re.search(r"\]\(([^)]+)\)", line)
            if match:
                image = Image(str((source.parent / match[1]).resolve()))
                ratio = min(480 / image.imageWidth, 550 / image.imageHeight)
                image.drawWidth, image.drawHeight = (
                    image.imageWidth * ratio,
                    image.imageHeight * ratio,
                )
                story.extend([image, Spacer(1, 8)])
        else:
            lines = [line]
            while (
                index + 1 < len(content)
                and content[index + 1].strip()
                and not content[index + 1].startswith(("#", "|", "```", "!["))
            ):
                index += 1
                lines.append(content[index].strip())
            separator = "" if re.search(r"[\u4e00-\u9fff]", "".join(lines)) else " "
            story.append(Paragraph(text(separator.join(lines)), body))
        index += 1
    output.parent.mkdir(parents=True, exist_ok=True)
    doc = SimpleDocTemplate(
        str(output),
        pagesize=A4,
        leftMargin=56,
        rightMargin=56,
        topMargin=52,
        bottomMargin=48,
        title=content[0][2:],
        author="",
        subject="通用毕业设计初稿",
    )

    def footer(canvas, document):
        canvas.setFont("CJK", 9)
        canvas.setFillColor(colors.HexColor("#666666"))
        canvas.drawCentredString(A4[0] / 2, 26, str(document.page))

    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    print(output)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--font", type=Path, required=True)
    args = parser.parse_args()
    build(args.source.resolve(), args.output.resolve(), args.font.resolve())
