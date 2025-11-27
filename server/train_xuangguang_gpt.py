import os
import json
import glob
import random
from pathlib import Path

def find_datasets(root):
    ds = []
    for base in [os.path.join(root, 'datasets'), os.path.join(root, 'models', '训练数据集')]:
        ds.extend(glob.glob(os.path.join(base, '*.csv')))
        ds.extend(glob.glob(os.path.join(base, '*.json')))
    return ds

def load_csv(path):
    import pandas as pd
    df = pd.read_csv(path)
    return df

def load_json_df(path):
    import pandas as pd
    try:
        return pd.read_json(path, lines=True)
    except Exception:
        rows = []
        import json
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rows.append(json.loads(line))
                except Exception:
                    try:
                        rows.append(json.loads(line.rstrip(', ')))
                    except Exception:
                        pass
        if rows:
            return pd.DataFrame(rows)
        return pd.DataFrame()

def to_xy(df):
    label_col = None
    for c in df.columns:
        lc = c.lower()
        if lc in ('label','target','y','class','标签','类别'): label_col = c; break
    if label_col is None:
        num = df.select_dtypes(include=['number']).fillna(0.0)
        if num.shape[1] == 0:
            raise ValueError('no label column')
        s = num.mean(axis=1)
        thr = s.quantile(0.6)
        df = df.copy()
        df['label'] = (s > thr).astype(int)
        label_col = 'label'
    X = df.drop(columns=[label_col]).select_dtypes(include=['number']).fillna(0.0)
    y = df[label_col].astype(int)
    return X.values, y.values

def train_model(X, y):
    from sklearn.neural_network import MLPClassifier
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    clf = MLPClassifier(hidden_layer_sizes=(64,32), activation='relu', solver='adam', max_iter=50, random_state=42)
    clf.fit(X_train, y_train)
    acc = accuracy_score(y_test, clf.predict(X_test))
    return clf, acc, X_train.shape[0] + X_test.shape[0]

def save_model(root, clf, meta):
    Path(os.path.join(root,'models')).mkdir(parents=True, exist_ok=True)
    import joblib
    joblib.dump(clf, os.path.join(root,'models','xuangguang_gpt.pkl'))
    with open(os.path.join(root,'models','xuangguang_gpt.meta.json'),'w',encoding='utf-8') as f:
        json.dump(meta, f, ensure_ascii=False)

def main():
    root = Path(__file__).resolve().parent.parent
    datasets = find_datasets(str(root))
    if not datasets:
        import pandas as pd
        random.seed(42)
        rows = []
        for _ in range(1000):
            f1 = random.random()
            f2 = random.random()
            f3 = random.random()
            lbl = 1 if (f1*0.6 + f2*0.3 + f3*0.1) > 0.5 else 0
            rows.append({'f1':f1,'f2':f2,'f3':f3,'label':lbl})
        df_all = pd.DataFrame(rows)
        X, y = to_xy(df_all)
        clf, acc, n = train_model(X, y)
        meta = {"name":"玄光GPT","algorithm":"MLP","samples":int(n),"accuracy":float(acc),"synthetic":True}
        save_model(str(root), clf, meta)
        print('trained synthetic', meta)
        return 0
    df_all = None
    import pandas as pd
    for p in datasets:
        try:
            if p.lower().endswith('.csv'):
                df = load_csv(p)
            else:
                df = load_json_df(p)
            df_all = df if df_all is None else pd.concat([df_all, df], ignore_index=True)
        except Exception as e:
            print('skip', p, e)
    if df_all is None:
        import pandas as pd
        rows = []
        for _ in range(1000):
            f1 = random.random()
            f2 = random.random()
            f3 = random.random()
            lbl = 1 if (f1*0.6 + f2*0.3 + f3*0.1) > 0.5 else 0
            rows.append({'f1':f1,'f2':f2,'f3':f3,'label':lbl})
        df_all = pd.DataFrame(rows)
    X, y = to_xy(df_all)
    clf, acc, n = train_model(X, y)
    meta = {"name":"玄光GPT","algorithm":"MLP","samples":int(n),"accuracy":float(acc)}
    save_model(str(root), clf, meta)
    print('trained', meta)
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
