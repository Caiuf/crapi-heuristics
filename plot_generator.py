"""
plot_generator.py - Gerador determinístico de figuras acadêmicas (300 DPI) para o Capítulo 4 do TCC.
Gera:
  1. fig1_estudo_ablacao.png (Eficácia vs. Latência Sub-ms no Estudo de Ablação)
  2. fig2_calibracao_csic2010.png (Evolução FPR, Recall e F1-Score: Piso MAD e CSIC 2010)
  3. fig3_matrizes_confusao.png (Matrizes de Confusão do Pipeline Completo e do CSIC 2010)
"""
import matplotlib.pyplot as plt
import numpy as np


def generate_tcc_figures() -> None:
    plt.rcParams.update({
        "font.family": "sans-serif",
        "font.size": 10,
        "axes.edgecolor": "#333333",
        "axes.linewidth": 0.8
    })

    # =========================================================================
    # FIGURA 2 DO TCC: Estudo de Ablação (Eficácia vs. Latência)
    # =========================================================================
    modes = [
        "1ª Barreira\n(volumetric_only)",
        "2ª Barreira\n(payload_only)",
        "Pipeline Completo\n(full Fail-Fast)"
    ]
    recall_vals = [55.0, 45.0, 100.0]
    f1_vals = [70.97, 62.07, 100.0]
    lat_mean = [0.0496, 0.1381, 0.2062]
    lat_p99 = [0.1225, 0.2408, 0.3886]

    x = np.arange(len(modes))
    width = 0.32

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5), dpi=300)

    rects1 = ax1.bar(x - width / 2, recall_vals, width, label="Recall (%)", color="#1f77b4")
    rects2 = ax1.bar(x + width / 2, f1_vals, width, label="F1-Score (%)", color="#2ca02c")
    ax1.set_ylabel("Percentual (%)")
    ax1.set_title("A) Eficácia Discriminativa no Estudo de Ablação")
    ax1.set_xticks(x)
    ax1.set_xticklabels(modes)
    ax1.set_ylim(0, 115)
    ax1.grid(axis="y", linestyle="--", alpha=0.5)
    ax1.legend(loc="upper left")
    ax1.bar_label(rects1, fmt="%.1f%%", padding=3, fontsize=8)
    ax1.bar_label(rects2, fmt="%.2f%%", padding=3, fontsize=8)

    rects3 = ax2.bar(x - width / 2, lat_mean, width, label="Latência Média (ms)", color="#ff7f0e")
    rects4 = ax2.bar(x + width / 2, lat_p99, width, label="Latência P99 (ms)", color="#d62728")
    ax2.set_ylabel("Tempo de Inspeção (ms)")
    ax2.set_title("B) Sobrecarga Computacional por Camada (Sub-ms)")
    ax2.set_xticks(x)
    ax2.set_xticklabels(modes)
    ax2.set_ylim(0, 0.46)
    ax2.grid(axis="y", linestyle="--", alpha=0.5)
    ax2.legend(loc="upper left")
    ax2.bar_label(rects3, fmt="%.4f", padding=3, fontsize=8)
    ax2.bar_label(rects4, fmt="%.4f", padding=3, fontsize=8)

    plt.tight_layout()
    plt.savefig("fig1_estudo_ablacao.png", dpi=300)
    plt.close()

    # =========================================================================
    # FIGURA 3 DO TCC: Evolução da Calibração e Dataset Público CSIC 2010
    # =========================================================================
    scenarios = [
        "Exp. 1: s/ Piso MAD\n(Pré-Calibração)",
        "Exp. 3: CSIC 2010\n(Pré-Ajuste SQLmap)",
        "Exp. 3: CSIC 2010\n(Versão Final Calibrada)"
    ]
    fpr_s = [19.22, 0.0, 0.0]
    rec_s = [100.0, 59.5, 96.0]
    f1_s = [53.62, 74.61, 97.96]

    x2 = np.arange(len(scenarios))
    w2 = 0.25

    fig2, ax = plt.subplots(figsize=(8.5, 4.5), dpi=300)
    b1 = ax.bar(x2 - w2, fpr_s, w2, label="FPR (%)", color="#d62728")
    b2 = ax.bar(x2, rec_s, w2, label="Recall (%)", color="#1f77b4")
    b3 = ax.bar(x2 + w2, f1_s, w2, label="F1-Score (%)", color="#2ca02c")

    ax.set_ylabel("Percentual (%)")
    ax.set_title("Impacto da Calibração Estatística (MAD) e Léxica (CSIC 2010 / sqlmap)")
    ax.set_xticks(x2)
    ax.set_xticklabels(scenarios)
    ax.set_ylim(0, 115)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    ax.legend(loc="upper right")
    ax.bar_label(b1, fmt="%.2f%%", padding=3, fontsize=8)
    ax.bar_label(b2, fmt="%.1f%%", padding=3, fontsize=8)
    ax.bar_label(b3, fmt="%.2f%%", padding=3, fontsize=8)

    plt.tight_layout()
    plt.savefig("fig2_calibracao_csic2010.png", dpi=300)
    plt.close()

    # =========================================================================
    # FIGURA 4 DO TCC: Matrizes de Confusão (Padrão Visual UniCEUB em 300 DPI)
    # =========================================================================
    cm_synthetic = np.array([[900, 0], [0, 100]])
    cm_csic2010 = np.array([[800, 0], [8, 192]])

    fig3, axes = plt.subplots(1, 2, figsize=(10, 4.3), dpi=300)
    titles = [
        "A) Pipeline Completo (Dataset Sintético crAPI)\nFPR = 0,0% | Recall = 100,0% | F1 = 100,0%",
        "B) Pipeline Completo (Dataset Real CSIC 2010)\nFPR = 0,0% | Recall = 96,0% | F1 = 97,96%"
    ]

    for ax_cm, cm, title in zip(axes, [cm_synthetic, cm_csic2010], titles):
        im = ax_cm.imshow(cm, interpolation="nearest", cmap="viridis")
        ax_cm.set_title(title, fontsize=9.5, pad=10)
        fig3.colorbar(im, ax=ax_cm, fraction=0.046, pad=0.04)

        classes = ["0 (Normal)", "1 (Anômalo)"]
        ax_cm.set_xticks([0, 1])
        ax_cm.set_yticks([0, 1])
        ax_cm.set_xticklabels(classes)
        ax_cm.set_yticklabels(classes)
        ax_cm.set_ylabel("Rótulo Real (True label)")
        ax_cm.set_xlabel("Decisão do Motor (Predicted label)")

        thresh = cm.max() / 2.0
        for i in range(2):
            for j in range(2):
                ax_cm.text(
                    j, i, format(cm[i, j], "d"),
                    ha="center", va="center",
                    fontsize=12, fontweight="bold",
                    color="#222222" if cm[i, j] > thresh else "white"
                )

    plt.tight_layout()
    plt.savefig("fig3_matrizes_confusao.png", dpi=300)
    plt.close()

    print("Figuras geradas com sucesso: 'fig1_estudo_ablacao.png', 'fig2_calibracao_csic2010.png' e 'fig3_matrizes_confusao.png'.")


if __name__ == "__main__":
    generate_tcc_figures()