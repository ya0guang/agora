import seaborn as sns

from scipy.stats import  binom
from matplotlib import pyplot as plt
from matplotlib.lines import Line2D

plt.rcParams['font.family'] = 'Times New Roman'
plt.rcParams['font.size'] = 20
plt.figure(figsize=(10, 5), dpi=300)

colors = ["#1f77b4", "#2ca02c","#ff7f0e"]

n = 200
P = [0.7, 0.4, 0.1]
Q = [0.5, 0.8]

basic_reward = 0.021

line_styles = ["-","--","-."]

data = []
for a, p in enumerate(P):
    for b, q in enumerate(Q):
        probability = p
        line_style = line_styles[b]
        array = []
        array_backup = []
        for i in range(1, 51):
            for j in range(1, 10000):
                prob = (1 - n * binom.cdf(i-1, j, probability))
                if prob > 0.99:
                    array.append(j*(basic_reward) / q)
                    break
        data.append(array)

        sns.lineplot(x=[i for i in range(1, 51)], y=array, linewidth=2*a+2, linestyle=line_style, color=colors[a])
legends = []
for i in range(3):
    legends.append(Line2D([0], [0], color=colors[-1-i], linewidth=6-2*i, linestyle='-', label=f"{int(P[-1-i]*100)}%"))
legend = plt.legend(handles=legends, title="p")
plt.gca().add_artist(legend)
legends = []
for i in range(2):
    legends.append(Line2D([0], [0], color="black", linewidth=4, linestyle=line_styles[i], label=f"{int(Q[i]*100)}%"))
legend = plt.legend(handles=legends, title="q", loc='upper left',  bbox_to_anchor=(0.23, 1))

plt.ylabel("Basic Reward Costs ($)")
plt.xlabel("Effectively Verified Times (T)")
plt.savefig("btm-cost.pdf", bbox_inches='tight')
